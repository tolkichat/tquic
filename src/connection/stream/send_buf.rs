// Copyright (c) 2023 The TQUIC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cmp;
use std::collections::VecDeque;
use std::ops::Range;

use bytes::Bytes;
use log::*;

use super::range_buf::RangeBuf;
use crate::ranges;
use crate::Error;
use crate::Result;

#[cfg(test)]
pub(crate) const SEND_BUFFER_SIZE: usize = 5;

#[cfg(not(test))]
pub(crate) const SEND_BUFFER_SIZE: usize = 4096;

/// Send-side stream buffer.
///
/// Buffer of outgoing retransmittable stream data.
///
/// New data is appended at the end of the stream, always.
#[derive(Debug, Default)]
pub struct SendBuf {
    /// Chunks of data to be sent, ordered by offset.
    /// Data written by application but not yet acknowledged.
    /// May or may not have been sent.
    pub(super) data: VecDeque<RangeBuf>,

    /// The index of the data block that will be sent next. This design is to
    /// improve the performance of reading next sent data from `data` queue.
    /// Note that pos will be decreased when data is lost and needs to be retransmitted.
    pos: usize,

    /// The maximum offset of data written by application in the stream.
    pub(super) write_off: u64,

    /// The first offset that has not been sent.
    pub(super) unsent_off: u64,

    /// Total size of `unacked_segments`
    //  unacked_len = self.write_off - self.ack_off()
    pub(super) unacked_len: usize,

    /// The maximum offset of data that can be sent in the stream.
    pub(super) max_data: u64,

    /// The offset of data that is blocked by flow control, if any.
    pub(super) blocked_at: Option<u64>,

    /// The final size of the stream, if known.
    pub(super) fin_off: Option<u64>,

    /// Whether the stream's send-side has been shutdown.
    /// If true, no more data can be written to the stream.
    pub(super) shutdown: bool,

    /// Ranges of data offsets that have been acknowledged.
    pub(super) acked: ranges::RangeSet,

    /// Ranges of data offsets that have been deemed lost.
    pub(super) retransmits: ranges::RangeSet,

    /// The error code received from the peer via STOP_SENDING.
    pub(super) error: Option<u64>,

    /// Unique trace id for debug logging.
    pub(super) trace_id: String,
}

impl SendBuf {
    /// Create a new send buffer with the given maximum stream data.
    pub(super) fn new(max_data: u64) -> SendBuf {
        SendBuf {
            max_data,
            ..SendBuf::default()
        }
    }

    /// Insert data at the end of the buffer.
    /// Return the number of bytes that actually got written.
    pub fn write(&mut self, mut data: Bytes, mut fin: bool) -> Result<usize> {
        let max_off = self.write_off + data.len() as u64;

        // Get the number of bytes that can be written to the stream.
        // Note: Here may return an error if the stream was stopped.
        let capacity = self.capacity()?;

        if data.len() > capacity {
            // Truncate the data to fit the stream's capacity.
            let len = capacity;
            data.truncate(len);

            // Clear the fin flag because we are not writing the full data.
            fin = false;
        }

        if let Some(fin_off) = self.fin_off {
            // Can't write more data after the final offset.
            if max_off > fin_off {
                return Err(Error::FinalSizeError);
            }

            // Fin flag can't be cancelled after it was set.
            if max_off == fin_off && !fin {
                return Err(Error::FinalSizeError);
            }
        }

        if fin {
            self.fin_off = Some(max_off);
        }

        // We can't do this check earlier because we need to check the fin flag.
        if data.is_empty() {
            return Ok(data.len());
        }

        let data_len = data.len();
        let mut len = 0;

        // Split the remaining data into consistently sized chunks to avoid fragmentation.
        // Note: Chunks return from Bytes::chunks() are slices, not what we want.
        while data.len() > SEND_BUFFER_SIZE {
            let chunk = data.split_to(SEND_BUFFER_SIZE);
            len += chunk.len();

            let fin = len == data_len && fin;
            let buf = RangeBuf::new(chunk, self.write_off, fin);

            self.write_off += buf.len() as u64;
            self.data.push_back(buf);
        }

        // Write the remaining data.
        if !data.is_empty() {
            let buf = RangeBuf::new(data, self.write_off, fin);

            self.write_off += buf.len() as u64;
            self.data.push_back(buf);
        }

        self.unacked_len += data_len;

        Ok(data_len)
    }

    /// Compute the next range to transmit on the stream and update state to account
    /// for that transmission.
    ///
    /// Return the range of bytes to transmit.
    pub(super) fn poll_transmit(&mut self, max_len: usize) -> Range<u64> {
        // 1. Check and Retransmit sent data
        if let Some(range) = self.retransmits.pop_min() {
            let end = cmp::min(range.end, range.start.saturating_add(max_len as u64));
            if end != range.end {
                self.retransmits.insert(end..range.end);
            }

            let rtx_range = range.start..end;
            trace!("{} poll_transmit, rtx range {:?}", self.trace_id, rtx_range);
            return rtx_range;
        }

        // 2. Transmit new data
        // Range: [self.unsent_off, min(write_off, self.unsent_off + max_len))
        let end = cmp::min(
            self.write_off,
            self.unsent_off.saturating_add(max_len as u64),
        );
        let new_range = self.unsent_off..end;
        trace!("{} poll_transmit, new range {:?}", self.trace_id, new_range);
        self.unsent_off = end;
        new_range
    }

    /// Read the range-associated interval data, which may actually be a subset of
    /// the range. For example, in scenarios where the data in the send buffer is not
    /// continuous, the caller should try again.
    pub(super) fn read_range(&mut self, range: Range<u64>) -> &[u8] {
        while let Some(segment) = self.data.get(self.pos) {
            if range.start >= segment.off() && range.start < segment.max_off() {
                let start = (range.start - segment.off()) as usize;
                let end = ((range.end - segment.off()) as usize).min(segment.len());

                // The entire data block will be read, increase the position.
                if end == segment.len() {
                    self.pos += 1;
                }

                return &segment[start..end];
            }

            self.pos += 1;
        }

        &[]
    }

    /// Read data from the send buffer, and write them into the given output buffer.
    /// Return output buffer length and fin flag.
    pub fn read(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();
        let out_off = self.send_off();
        // The caller of this function has already written the offset of the STREAM frame
        // into the header of the frame, so we must keep it consistent here.
        let mut next_off = out_off;

        while cap > 0
            && self.ready()
            && self.send_off() == next_off
            && self.send_off() < self.max_data
        {
            let range = self.poll_transmit(cap);
            // The data specified by the range may not be stored contiguously, so it
            // may not be retrieved by a single `read_range` call, so here we need to loop
            // until the range is completely copied into the given out buffer.
            let mut range = range.clone();

            let range_len: u64 = range.end - range.start;
            while range.start != range.end {
                let data = self.read_range(range.clone());
                let buf_len = data.len();

                out[len..len + buf_len].copy_from_slice(&data[..buf_len]);
                len += buf_len;
                range.start += buf_len as u64;
            }

            cap -= range_len as usize;
            next_off += range_len;
        }

        // Get the fin flag for the output buffer by matching the maximum offset of
        // the output buffer with the final offset of the stream(if any).
        //
        // Note: When send buffer only contains empty buffer with fin flag, send buffer
        // is not ready, but the fin flag will be read out.
        let fin = self.fin_off == Some(next_off);

        Ok((out.len() - cap, fin))
    }

    /// Return true if there is data to be sent.
    ///
    /// There may be some data inflight that has been sent but not yet acknowledged,
    /// even this is false.
    pub(super) fn ready(&self) -> bool {
        !self.data.is_empty() && self.send_off() < self.write_off
    }

    /// Update the stream's send-side max_data limit.
    pub(super) fn update_max_data(&mut self, max_data: u64) {
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Update the last offset at which the stream was blocked, if any.
    pub(super) fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }

    /// Get the last offset at which the stream was blocked, if any.
    pub(super) fn blocked_at(&self) -> Option<u64> {
        self.blocked_at
    }

    /// Return the maximum offset of data written by application
    pub(super) fn write_off(&self) -> u64 {
        self.write_off
    }

    /// Get the highest offset that has been consecutively acknowledged.
    //  Example: We get ack ranges [0, 50], [55, 60] then return 50.
    pub(super) fn ack_off(&self) -> u64 {
        match self.acked.iter().next() {
            // Only take the initial range into account if it covers the start
            // of the stream continuously, i.e.[0..N).
            Some(std::ops::Range { start: 0, end }) => end,
            Some(_) | None => 0,
        }
    }

    /// Insert the new ACK packet number range into the range set.
    pub(super) fn ack(&mut self, off: u64, len: usize) {
        self.acked.insert(off..off + len as u64);
    }

    /// Process the new ACK range, and try to delete the range data
    /// that has been acknowledged continuously(i.e.without holes).
    pub fn ack_and_drop(&mut self, off: u64, len: usize) {
        // Data queue is empty, we can clear the retransmit queue directly without any other processing.
        // There may be three cases:
        // 1. All data has been ACKed, i.e. the current ACK is a duplicate ACK;
        // 2. The stream received STOP_SENDING frame from the peer, and the data queue has been cleared;
        // 3. The stream has been actively RESET by the upper application, and the data queue has been cleared.
        if self.data.is_empty() {
            self.retransmits.clear();
            return;
        }

        trace!(
            "{} ack_and_drop range: {:?}, send_off {}, write_off {}, ack_off {}, pos {}",
            self.trace_id,
            Range {
                start: off,
                end: off + len as u64
            },
            self.send_off(),
            self.write_off(),
            self.ack_off(),
            self.pos
        );

        // Insert the new ACK range into the range set.
        // Note: The first acked range is always like [0, x).
        self.ack(off, len);

        // Spurious retransmission, remove them from retransmit queue.
        self.retransmits.remove(off..off + len as u64);

        // Get the highest contiguously acked offset.
        let ack_off = self.ack_off();

        // If there are gaps between [0, self.ack_off) and [off, off + len),
        // then we can't drop any data.
        if off > ack_off {
            return;
        }

        // Drop the data that has been contiguously acked.
        let base_off = self.write_off - self.unacked_len as u64;
        let mut to_advance: usize = (ack_off - base_off) as usize;
        self.unacked_len -= to_advance;
        let mut drop_blocks = 0;
        while to_advance > 0 {
            let front = self.data.front_mut().unwrap();

            // Drop the data block if it has been fully acknowledged.
            if front.len() <= to_advance {
                to_advance -= front.len();
                self.data.pop_front();
                drop_blocks += 1;
            // Advance the data block if it has been partially acknowledged.
            } else {
                front.advance(to_advance);
                to_advance = 0;
            }
        }

        // Note: We should take spuriously retransmitted scenario into account.
        // When a packet is deemed lost, causing the pos to be rolled back, but
        // the subsequent ack of the packet is received, the pos may be reduced
        // excessively, and we need to avoid this situation.
        self.pos = self.pos.saturating_sub(drop_blocks);

        if self.data.len() * 4 < self.data.capacity() {
            self.data.shrink_to_fit();
        }
    }

    /// Queue a range of sent but unacknowledged data(deemed lost) to the retransmission
    /// range set.
    pub fn retransmit(&mut self, off: u64, len: usize) {
        let mut start = off;
        let mut end = off + len as u64;
        let old_send_off = self.send_off();

        if self.data.is_empty() {
            return;
        }

        if end <= self.ack_off() {
            return;
        }

        // unsent data can't be lost.
        #[cfg(test)]
        if end > self.unsent_off {
            return;
        }

        for range in self.acked.iter() {
            // The retransmit range is before the current range, stop searching.
            if end <= range.start {
                break;
            }

            // The retransmit range is after the range, go to the next range.
            if start >= range.end {
                continue;
            }

            // The retransmit range is overlapped with the acked range, update the range.
            if start < range.start {
                if end <= range.end {
                    // The second half of the retransmit range is covered by the current acked range,
                    // only the first half of the retransmit range needs to be retransmitted.
                    end = range.start;
                    break;
                } else {
                    // start < range.start && end > range.end
                    // The retransmit range crosses the current acked range, split the retransmit
                    // range into two parts, and the first part needs to be retransmitted, and the
                    // second part will be checked against the next acked range.
                    self.retransmits.insert(start..range.start);
                    start = range.end;
                    continue;
                }
            } else {
                // start >= range.start && start < range.end
                if end <= range.end {
                    // Fully covered by the current acked range, clear the retransmit range.
                    end = start;
                    break;
                } else {
                    // start >= range.start && start < range.end && end > range.end
                    // The first half of the retransmit range is covered by the current acked range,
                    // only the second half of the retransmit range may needs to be retransmitted.
                    start = range.end;
                    continue;
                }
            }
        }

        self.retransmits.insert(start..end);

        // 1. If and only if we found new lost data, and the lost data is before the lowest
        // retransmits range, we should update the position of next data block to be sent.
        // 2. This design is to decrease the number of times we need to update the position
        // when we found large number of lost data during one processing cycle.
        if self.send_off() < old_send_off {
            // We don't update the position to the accurate value here. Instead, we update it
            // during the read_range phase, which can reduce the number of update operations.
            self.pos = 0;
        }
    }

    /// Return the first unacked subrange in `range`.
    pub fn filter_acked(&self, range: Range<u64>) -> Option<Range<u64>> {
        self.acked.filter(range)
    }

    /// Reset the stream at the current offset and clean up the cached data.
    ///
    /// Upon receiving a STOP_SENDING frame from peer, or actively shutting down
    /// by application, send a RESET_STREAM frame to peer to reset the stream.
    ///
    /// Return the final offset and the number of bytes that have not been sent.
    pub(super) fn reset(&mut self) -> (u64, u64) {
        let unsent_len = self.write_off.saturating_sub(self.unsent_off);

        self.fin_off = Some(self.unsent_off);

        // Clean up all buffered data.
        self.data.clear();

        // Mark all sent data as acknowledged.
        self.ack(0, self.unsent_off as usize);

        self.pos = 0;
        self.write_off = self.unsent_off;

        (self.fin_off.unwrap(), unsent_len)
    }

    /// Reset the stream and record the received error code
    /// after receiving a STOP_SENDING frame from peer.
    pub(super) fn stop(&mut self, error_code: u64) -> Result<(u64, u64)> {
        if self.error.is_some() {
            return Err(Error::Done);
        }

        let (fin_off, unsent) = self.reset();

        self.error = Some(error_code);

        Ok((fin_off, unsent))
    }

    /// Shutdown the stream's send-side.
    ///
    /// Return the stream final size and the number of bytes that have not been sent.
    pub(super) fn shutdown(&mut self) -> Result<(u64, u64)> {
        if self.shutdown {
            return Err(Error::Done);
        }

        self.shutdown = true;

        Ok(self.reset())
    }

    /// Return true if the send-side of the stream has been shutdown by application.
    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Return true if the stream's send-side final size is known, and the application
    /// has already written data up to that point.
    pub(super) fn is_fin(&self) -> bool {
        self.fin_off == Some(self.write_off)
    }

    /// Return true if the stream's send-side enters a terminal state.
    ///
    /// When the stream's send-side final size is known, and all stream data
    /// has been successfully acknowledged, the stream enters a terminal state.
    pub(super) fn is_complete(&self) -> bool {
        match self.fin_off {
            Some(fin_off) => fin_off == 0 || self.acked == (0..fin_off),
            None => false,
        }
    }

    /// Return true if `STOP_SENDING` frame was received.
    pub fn is_stopped(&self) -> bool {
        self.error.is_some()
    }

    /// Get the lowest offset of data to be sent.
    pub fn send_off(&self) -> u64 {
        // retransmits.min little than unsent_off, always.
        if !self.retransmits.is_empty() {
            self.retransmits.min().unwrap()
        } else {
            self.unsent_off
        }
    }

    /// Get the maximum offset of data that peer allows to send.
    pub(super) fn max_data(&self) -> u64 {
        self.max_data
    }

    /// Get the stream send capacity. Return an error if the stream is stopped,
    /// else return the number of bytes that can be written to the stream.
    pub(super) fn capacity(&self) -> Result<usize> {
        match self.error {
            // Stream was stopped by the peer.
            Some(e) => Err(Error::StreamStopped(e)),
            None => Ok((self.max_data - self.write_off) as usize),
        }
    }
}
