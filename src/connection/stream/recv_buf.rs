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
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::time;

use bytes::Bytes;
use log::*;

use super::range_buf::RangeBuf;
use crate::connection::flowcontrol;
use crate::Error;
use crate::Result;

/// Receive-side stream buffer.
///
/// The stream data received from peer is buffered in a BTreeMap ordered by
/// offset in ascending order. Contiguous data can then be read into a slice.
#[derive(Debug, Default)]
pub struct RecvBuf {
    /// Chunks of data received from the peer ordered by offset
    /// but have not yet been read by the application.
    /// Note: The key is the maximum offset of the chunk, not the lowest.
    pub(super) data: BTreeMap<u64, RangeBuf>,

    /// The lowest data offset that has yet to be read by the application.
    pub(super) read_off: u64,

    /// The largest data offset that has been received on this stream.
    pub(super) recv_off: u64,

    /// The final stream offset received from the peer, if any.
    pub(super) fin_off: Option<u64>,

    /// The error code received from the RESET_STREAM frame.
    pub(super) error: Option<u64>,

    /// Whether the stream's Receive-side has been shut down.
    pub(super) shutdown: bool,

    /// Receive-side stream flow controller.
    flow_control: flowcontrol::FlowControl,

    /// Unique trace id for debug logging.
    pub(super) trace_id: String,
}

impl RecvBuf {
    /// Create a new receive-side stream buffer with given flow control limits.
    pub(super) fn new(max_data: u64, max_window: u64) -> RecvBuf {
        RecvBuf {
            flow_control: flowcontrol::FlowControl::new(max_data, max_window),
            ..RecvBuf::default()
        }
    }

    /// Insert the given chunk of data into the buffer.
    pub fn write(&mut self, offset: u64, data: Bytes, fin: bool) -> Result<()> {
        let buf = RangeBuf::new(data, offset, fin);

        // 1. Validate the legality of stream flow control limits
        // An endpoint MUST terminate a connection with an error of type FLOW_CONTROL_ERROR
        // if it receives more data than the largest maximum stream data that it has sent
        // for the affected stream.
        if buf.max_off() > self.max_data() {
            return Err(Error::FlowControlError);
        }

        // 2. Validate the legality of final size constraints
        if let Some(fin_off) = self.fin_off {
            // A receiver SHOULD treat receipt of data at or beyond the final size as an
            // error of type FINAL_SIZE_ERROR.
            if buf.max_off() > fin_off {
                return Err(Error::FinalSizeError);
            }

            // Once a final size for a stream is known, it cannot change. If a STREAM
            // frame is received indicating a change in the final size for the stream,
            // an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.
            if buf.fin() && fin_off != buf.max_off() {
                return Err(Error::FinalSizeError);
            }
        }

        // An endpoint received a STREAM frame containing a final size that was lower than
        // the size of stream data that was already received.
        if buf.fin() && buf.max_off() < self.recv_off {
            return Err(Error::FinalSizeError);
        }

        // 3. Check if the stream's receive-side is finished
        if self.is_fin() {
            return Ok(());
        }

        // If the buffer with a FIN flag, then set the final size of the stream
        // to the maximum offset of the buffer.
        if buf.fin() {
            self.fin_off = Some(buf.max_off());
        }

        // Do nothing if the buffer is empty and without fin flag.
        if !buf.fin() && buf.is_empty() {
            return Ok(());
        }

        // 4. Check if the buffer overlaps with existing data blocks
        // Check if data is fully duplicated, that is the buffer's max offset is
        // lower or equal to the lowest data offset that has yet to be read by
        // the application.
        if self.read_off >= buf.max_off() {
            // Exception case: Empty buffer with FIN flag.
            if !buf.is_empty() {
                return Ok(());
            }
        }

        // The newly received data may overlap with existing data blocks, and
        // it may be split into multiple segments before being stored.
        let mut tmp_bufs = VecDeque::with_capacity(2);
        tmp_bufs.push_back(buf);

        'outer_loop: while let Some(mut buf) = tmp_bufs.pop_front() {
            // Bytes up to self.read_off have already been consumed by application
            // so we should not buffer them again, just discard them.
            if self.read_off() > buf.off() {
                buf.advance((self.read_off() - buf.off()) as usize);
            }

            // Handle overlapping buffer or merge an empty final buffer.
            if buf.off() < self.recv_off() || buf.is_empty() {
                for (_, b) in self.data.range(buf.off()..) {
                    let off = buf.off();

                    // New buffer cannot overlap with any of the following buffers.
                    if b.off() > buf.max_off() {
                        break;
                    }
                    // New buffer completely overlaps with the existing one.
                    // i.e.[b.start  [buf.start, buf.end)  b.end)
                    else if off >= b.off() && buf.max_off() <= b.max_off() {
                        continue 'outer_loop;
                    }
                    // The first half of the buffer "buf" overlaps with the existing
                    // buffer "b". Advance the buffer "buf" to the end of the existing
                    // buffer "b".
                    // i.e. b.start < buf.start < b.end, discard [buf.start, b.end),
                    // and store buf = buf[b.end, buf.end)
                    else if off >= b.off() && off < b.max_off() {
                        buf.advance((b.max_off() - off) as usize);
                    }
                    // The second half of the buffer "buf" overlaps with the existing
                    // buffer "b". Use "split_off" to split the buffer, insert the first
                    // half of "buf" into "BTreeMap" after "for" loop, and the second
                    // half may still overlap with the existing part of "buf". Insert it
                    // into the temporary "VecDeque" for further processing.
                    // i.e. buf.start < b.start and buf.end > b.start
                    // [buf.start, b.start) will be insert to "BTreeMap"
                    // [b.start, buf.end) insert into the temp "VecDeque"
                    else if off < b.off() && buf.max_off() > b.off() {
                        tmp_bufs.push_back(buf.split_off((b.off() - off) as usize));
                    }
                }
            }

            // update stream received offset to max_off
            self.recv_off = cmp::max(self.recv_off, buf.max_off());

            if !self.shutdown {
                // Here we take buf.max_off as key but not buf.off,
                // because buf.off maybe changed while application consuming buf partially.
                self.data.insert(buf.max_off(), buf);
            }
        }

        Ok(())
    }

    /// Read data from the receive buffer, and write them into the given output buffer.
    ///
    /// Currently, only contiguous data can be consumed by application. If there is no
    /// data at the expected read offset, return `Done`.
    ///
    /// On success the amount of data read, and a flag indicating if there is
    /// no more data in the buffer, are returned as a tuple.
    pub fn read(&mut self, out: &mut [u8]) -> Result<(usize, bool)> {
        let mut len = 0;
        let mut cap = out.len();

        // Only contiguous data can be consumed by application.
        if !self.ready() {
            return Err(Error::Done);
        }

        // The stream has been reset by the peer.
        if let Some(e) = self.error {
            // An empty buffer with FIN flag may be left in the buffer when the stream
            // is reset, because the final offset of the stream is not known when the
            // stream is reset.
            self.data.clear();
            return Err(Error::StreamReset(e));
        }

        while cap > 0 && self.ready() {
            let mut entry = match self.data.first_entry() {
                Some(entry) => entry,
                None => break,
            };

            let buf = entry.get_mut();
            let buf_len = cmp::min(buf.len(), cap);
            out[len..len + buf_len].copy_from_slice(&buf[..buf_len]);

            // Update the lowest data offset that has yet to be read by the application.
            self.read_off += buf_len as u64;

            len += buf_len;
            cap -= buf_len;

            if buf_len < buf.len() {
                buf.consume(buf_len);

                // Reached the maximum capacity, stop reading.
                break;
            }

            // The data in current entry has all been consumed.
            entry.remove();
        }

        // Update consumed bytes for future stream-level flow control.
        self.flow_control.increase_read_off(len as u64);

        Ok((len, self.is_fin()))
    }

    /// Return true if the stream has buffered data to be read or an error to
    /// be collected.
    pub(super) fn ready(&self) -> bool {
        match self.data.first_key_value() {
            Some((_, buf)) => buf.off() == self.read_off,
            None => false,
        }
    }

    /// Receive RESET_STREAM frame from peer, reset the stream at the given offset.
    ///
    /// If the recv side is not shutdown by the application, an empty buffer with
    /// FIN will be written to the recv buffer to notify the application that it
    /// has been reset by its peer.
    pub fn reset(&mut self, error_code: u64, final_size: u64) -> Result<usize> {
        // Once a final size for a stream is known, it cannot change. If a RESET_STREAM
        // frame is received indicating a change in the final size for the stream,
        // an endpoint SHOULD respond with an error of type FINAL_SIZE_ERROR.
        if let Some(fin_off) = self.fin_off {
            if fin_off != final_size {
                return Err(Error::FinalSizeError);
            }
        }

        // An endpoint received a RESET_STREAM frame containing a final size that was
        // lower than the size of stream data that was already received.
        if final_size < self.recv_off {
            return Err(Error::FinalSizeError);
        }

        // Align the consumption of connection flow control in bytes
        let max_rx_off_delta = final_size - self.recv_off;

        // Duplicate RESET_STREAM frame.
        if self.error.is_some() {
            return Ok(max_rx_off_delta as usize);
        }

        self.error = Some(error_code);

        // Discard all buffered data.
        self.data.clear();

        // Notify application that the stream has been reset by the peer.
        trace!(
            "Write an empty buffer with FIN to stream recv {:}",
            self.trace_id
        );
        self.write(final_size, Bytes::new(), true)?;

        self.read_off = final_size;

        Ok(max_rx_off_delta as usize)
    }

    /// Shutdown the stream's receive-side.
    ///
    /// After this operation, any subsequent data received on the stream will be discarded.
    pub(super) fn shutdown(&mut self) -> Result<u64> {
        if self.shutdown {
            return Err(Error::Done);
        }

        // After shutdown flag is set, all subsequent data received on the stream
        // will be discarded.
        self.shutdown = true;

        let unread_len = self.recv_off() - self.read_off();

        // Discard all buffered data.
        self.data.clear();

        // Set application read offset as the largest received offset.
        self.read_off = self.recv_off();

        Ok(unread_len)
    }

    /// Apply the new local flow control limit.
    pub fn update_max_data(&mut self, now: time::Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Get the next max_data limit, which will be sent to peer in MAX_STREAM_DATA frame.
    pub fn max_data_next(&mut self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Get the local current flow control limit.
    pub(super) fn max_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Get the local current flow control window.
    pub fn window(&self) -> u64 {
        self.flow_control.window()
    }

    /// Autotune the local flow control window size.
    pub fn autotune_window(&mut self, now: time::Instant, srtt: time::Duration) {
        self.flow_control.autotune_window(now, srtt);
    }

    /// Get the lowest data offset that has yet to be read by the application.
    pub(super) fn read_off(&self) -> u64 {
        self.read_off
    }

    /// Get the largest offset that has been received so far.
    pub(super) fn recv_off(&self) -> u64 {
        self.recv_off
    }

    /// Return true if we should send `MAX_STREAM_DATA` frame to peer to update
    /// the local flow control limit.
    pub(super) fn should_send_max_data(&self) -> bool {
        self.fin_off.is_none() && self.flow_control.should_send_max_data()
    }

    /// Return true if the stream's receive-side has been shutdown by application.
    pub(super) fn is_shutdown(&self) -> bool {
        self.shutdown
    }

    /// Return true if the stream's receive-side final size is known, and the
    /// application has read all data from the stream.
    pub(super) fn is_fin(&self) -> bool {
        self.fin_off == Some(self.read_off)
    }

    /// Return true if the stream's receive-side is complete.
    ///
    /// Actually, this is same as `is_fin()`.
    pub(super) fn is_complete(&self) -> bool {
        self.fin_off == Some(self.read_off)
    }
}
