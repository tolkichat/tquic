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

#![allow(dead_code)]

pub(crate) mod concurrency;
pub(crate) mod range_buf;
pub(crate) mod recv_buf;
pub(crate) mod send_buf;
pub(crate) mod stream_state;
pub(crate) mod transport_params;

#[cfg(test)]
mod tests;

use std::any::Any;
use std::cmp;
use std::collections::btree_map;
use std::collections::hash_map;
use std::collections::BTreeMap;
use std::collections::BinaryHeap;
use std::collections::VecDeque;
pub(crate) use std::ops::Range;
use std::time;
use std::time::Instant;

use bytes::Buf;
use bytes::BufMut;
pub(crate) use bytes::Bytes;
use bytes::BytesMut;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use log::*;
use rustc_hash::FxHashMap;
use rustc_hash::FxHashSet;
use smallvec::SmallVec;

pub(crate) use concurrency::ConcurrencyControl;
use concurrency::SendCapacity;
use concurrency::StreamPriorityQueue;
pub(crate) use range_buf::RangeBuf;
pub(crate) use send_buf::SEND_BUFFER_SIZE;
pub(crate) use stream_state::is_local;

use crate::connection::flowcontrol;
use crate::ranges;
pub(crate) use crate::Error;
use crate::Event;
use crate::EventQueue;
pub(crate) use crate::Result;
pub(crate) use crate::Shutdown;
use crate::TransportParams;
use crate::MAX_STREAMS_PER_TYPE;

pub use recv_buf::RecvBuf;
pub use send_buf::SendBuf;
pub use stream_state::is_bidi;
pub use stream_state::Stream;
pub use stream_state::StreamIter;
pub use transport_params::StreamTransportParams;

pub type StreamIdHashMap<V> = FxHashMap<u64, V>;
pub type StreamIdHashSet = FxHashSet<u64>;

// Receiver stream flow control window default value, 32KB.
pub(crate) const DEFAULT_STREAM_WINDOW: u64 = 32 * 1024;

// Receiver stream flow control window max value, 6MB.
pub const MAX_STREAM_WINDOW: u64 = 6 * 1024 * 1024;

// Receiver connection flow control window default value, 48KB.
// Note that here we set the default value of the connection-level flow control window
// to be 1.5 times the size of the stream-level flow control window, i.e. 1.5 * 32KB.
pub const DEFAULT_CONNECTION_WINDOW: u64 = 48 * 1024;

// The maximum size of the receiver connection flow control window.
pub const MAX_CONNECTION_WINDOW: u64 = 15 * 1024 * 1024;

/// Stream manager for keeps track of streams on a QUIC Connection.
#[derive(Default)]
pub struct StreamMap {
    /// Whether it serves as a server.
    is_server: bool,

    /// Collection of streams that are organized and accessed by stream ID.
    streams: StreamIdHashMap<Stream>,

    /// Streams that have outstanding data ready to be sent to the peer,
    /// and categorized by their urgency, lower value means higher priority.
    sendable: BTreeMap<u8, StreamPriorityQueue>,

    /// Streams that have outstanding data can be read by the application.
    readable: StreamIdHashSet,

    /// Streams that have enough flow control capacity to be written to,
    /// and is not finished.
    writable: StreamIdHashSet,

    /// Streams that are shutdown on the send side by the application prematurely
    /// or received STOP_SENDING frame from the peer.
    ///
    /// Current endpoint should send a RESET_STREAM frame with the error code and
    /// final size values in the tuple of the map elements to the peer.
    reset: StreamIdHashMap<(u64, u64)>,

    /// Streams that are shutdown on the receive side, and need to send
    /// a STOP_SENDING frame.
    stopped: StreamIdHashMap<u64>,

    /// Keep track of IDs of previously closed streams. It can grow and use up a
    /// lot of memory, so it is used only in unit tests.
    #[cfg(test)]
    closed: StreamIdHashSet,

    /// Streams that peer are almost out of flow control capacity, and
    /// need local endpoint to send a MAX_STREAM_DATA frame to the peer.
    almost_full: StreamIdHashSet,

    /// Streams that are blocked on the send-side, and need to send a
    /// STREAM_DATA_BLOCKED frame to the peer. The value of the map elements is
    /// the stream offset at which the stream is blocked.
    data_blocked: StreamIdHashMap<u64>,

    /// Streams concurrency control.
    concurrency_control: ConcurrencyControl,

    /// Connection receive-side flow control.
    flow_control: flowcontrol::FlowControl,

    /// Connection send-side flow control.
    send_capacity: SendCapacity,

    /// The maximum stream receive-side flow control window, it is inherited
    /// from the connection configuration, and applies to all streams.
    max_stream_window: u64,

    /// Connection received-side flow control capacity almost full,
    /// local endpoint should issue more credit by sending a MAX_DATA
    /// frame to the peer.
    pub rx_almost_full: bool,

    /// Stream id for next bidirectional stream.
    next_stream_id_bidi: u64,

    /// Stream id for next unidirectional stream.
    next_stream_id_uni: u64,

    /// Peer transport parameters.
    peer_transport_params: StreamTransportParams,

    /// Local transport parameters.
    local_transport_params: StreamTransportParams,

    /// Events sent to the endpoint.
    pub(super) events: EventQueue,

    /// Unique trace id for debug logging.
    trace_id: String,
}

impl StreamMap {
    /// Create a new `StreamMap`.
    pub fn new(
        is_server: bool,
        max_connection_window: u64,
        max_stream_window: u64,
        local_params: StreamTransportParams,
    ) -> StreamMap {
        StreamMap {
            is_server,

            concurrency_control: ConcurrencyControl::new(
                local_params.initial_max_streams_bidi,
                local_params.initial_max_streams_uni,
            ),

            flow_control: flowcontrol::FlowControl::new(
                local_params.initial_max_data,
                max_connection_window,
            ),

            send_capacity: SendCapacity::default(),

            max_stream_window,
            rx_almost_full: false,

            next_stream_id_bidi: if is_server { 1 } else { 0 },
            next_stream_id_uni: if is_server { 3 } else { 2 },

            local_transport_params: local_params,
            peer_transport_params: StreamTransportParams::default(),

            ..StreamMap::default()
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
    }

    /// Return a reference to the stream with the given ID if it exists, or `None`.
    fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or `None`.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
    }

    /// Create a new bidirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_bidi_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        let stream_id = self.next_stream_id_bidi;
        match self.stream_set_priority(stream_id, urgency, incremental) {
            Ok(_) => Ok(stream_id),
            Err(e) => Err(e),
        }
    }

    /// Create a new undirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_uni_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        let stream_id = self.next_stream_id_uni;
        match self.stream_set_priority(stream_id, urgency, incremental) {
            Ok(_) => Ok(stream_id),
            Err(e) => Err(e),
        }
    }

    /// Get the lowest offset of data to be read.
    pub fn stream_read_offset(&mut self, stream_id: u64) -> Option<u64> {
        match self.get_mut(stream_id) {
            Some(stream) => Some(stream.recv.read_off()),
            None => None,
        }
    }

    /// Read contiguous data from the stream's receive buffer into the given buffer.
    ///
    /// Return the number of bytes read and the `fin` flag if read successfully.
    /// Return `StreamStateError` if the stream closed or never opened.
    /// Return `Done` if the stream is not readable.
    pub fn stream_read(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        // Local initiated unidirectional streams are send-only, so we can't read from them.
        if !is_bidi(stream_id) && is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // If the stream is not exist, it may not be opened yet, or it was closed,
        // return `StreamStateError`.
        let stream = self.get_mut(stream_id).ok_or(Error::StreamStateError)?;

        // If stream is not readable, return `Done`.
        if !stream.is_readable() {
            trace!("{} stream is not readable", stream.trace_id);
            return Err(Error::Done);
        }

        let local = stream.local;

        let (read, fin) = match stream.recv.read(out) {
            Ok(v) => v,

            Err(e) => {
                trace!("{} stream read error: {:?}", stream.trace_id, e);

                // Stream recv-side maybe reset by peer, if it is complete, we should
                // remove it from the stream map, and collect it to `closed` streams set.
                if stream.is_complete() {
                    self.mark_closed(stream_id, local);
                }

                self.mark_readable(stream_id, false);
                return Err(e);
            }
        };

        // We can't move these two lines of code after the connection-level
        // flow_control check, otherwise there will be a variable borrowing problem.
        let readable = stream.is_readable();
        let complete = stream.is_complete();

        // Check if we need to send a `MAX_STREAM_DATA` frame to update
        // stream-level flow control.
        if stream.recv.should_send_max_data() {
            self.mark_almost_full(stream_id, true);
        }

        // Update connection-level flow control consumption, and check if we should
        // send a `MAX_DATA` frame to update connection-level flow control limit.
        self.flow_control.increase_read_off(read as u64);
        if self.flow_control.should_send_max_data() {
            self.rx_almost_full = true;
        }

        // After reading, we should remove it from the readable queue if it is not
        // readable at the present.
        if !readable {
            self.mark_readable(stream_id, false);
        }

        // If the stream is complete, we should remove it from the streams map and
        // collect it to the `closed` streams set.
        if complete {
            self.mark_closed(stream_id, local);
        }

        Ok((read, fin))
    }

    /// Get the maximum offset of data written by application
    pub fn stream_write_offset(&mut self, stream_id: u64) -> Option<u64> {
        match self.get_mut(stream_id) {
            Some(stream) => Some(stream.send.write_off()),
            None => None,
        }
    }

    /// Write data to the stream's send buffer.
    pub fn stream_write(&mut self, stream_id: u64, mut buf: Bytes, fin: bool) -> Result<usize> {
        // Peer initiated unidirectional streams are receive-only, so we can't write to them.
        if !is_bidi(stream_id) && !is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // If the connection-level flow control credit is not enough, mark the
        // the connection as blocked and schedule a `DATA_BLOCKED` frame to be sent.
        if self.max_tx_data_left() < buf.len() as u64 {
            self.update_data_blocked_at(Some(self.send_capacity.max_data));
        }

        let expect_written = buf.len();
        let capacity = self.send_capacity.capacity;

        // Get or create the stream if it was not created before.
        // If the stream was closed, return `Done`.
        let stream = self.get_or_create(stream_id, true)?;

        let was_writable = stream.is_writable();
        let was_sendable = stream.is_sendable();

        // When the connection's capacity is exhausted, if the input buffer is not empty,
        // return `Done`.
        if capacity == 0 && !buf.is_empty() {
            // Stream blocked by the connection's send capacity, must not affect
            // its writable state.
            if was_writable {
                self.mark_writable(stream_id, true);
            }

            // Stream blocked, but it still want to write, so we should mark it as want-write.
            let _ = self.want_write(stream_id, true);
            return Err(Error::Done);
        }

        // If the connection's send capacity is not enough, truncate the input
        // buffer with the capacity.
        let (fin, blocked_by_cap) = if capacity < buf.len() {
            buf.truncate(capacity);
            (false, true)
        } else {
            (fin, false)
        };

        // Save the buffer's length before its ownership moved.
        let buf_len = buf.len();

        let written = match stream.send.write(buf, fin) {
            Ok(v) => v,

            Err(e) => {
                self.mark_writable(stream_id, false);
                return Err(e);
            }
        };

        let urgency = stream.urgency;
        let incremental = stream.incremental;

        let sendable = stream.is_sendable();
        let writable = stream.is_writable();
        let empty_fin = buf_len == 0 && fin;

        if written < buf_len {
            let max_data = stream.send.max_data();

            if stream.send.blocked_at() != Some(max_data) {
                stream.send.update_blocked_at(Some(max_data));
                self.mark_blocked(stream_id, true, max_data);
            }
        } else {
            stream.send.update_blocked_at(None);
            self.mark_blocked(stream_id, false, 0);
        }

        // If the stream is sendable and it wasn't sendable before, push it to
        // the sendable queue.
        // Note: Buffer an empty block data with fin should be treated as sendable.
        if (sendable || empty_fin) && !was_sendable {
            self.push_sendable(stream_id, urgency, incremental);
        }

        if !writable {
            self.mark_writable(stream_id, false);
        } else if was_writable && blocked_by_cap {
            // Stream blocked by the connection's send capacity, must not affect
            // its writable state.
            self.mark_writable(stream_id, true);
        }

        self.send_capacity.capacity -= written;
        self.send_capacity.tx_data += written as u64;

        // Write partial data, mark the stream as want-write.
        if written < expect_written {
            let _ = self.want_write(stream_id, true);
        }

        // No data was written, it maybe limited by the stream-level flow control.
        if written == 0 && buf_len > 0 {
            return Err(Error::Done);
        }

        Ok(written)
    }

    /// Shutdown stream receive-side or send-side.
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        // We can't move this line to the match arm because of the borrow checker.
        let is_server = self.is_server;

        // If the stream was not created before or has been closed, return `Done`.
        let stream = self.get_mut(stream_id).ok_or(Error::Done)?;
        match direction {
            Shutdown::Read => {
                // Local initiated uni stream should not be shutdown in the receive-side.
                if is_local(stream_id, is_server) && !is_bidi(stream_id) {
                    return Err(Error::StreamStateError);
                }

                let unread_len = stream.recv.shutdown()?;

                // If the stream doesn't enter terminal state, sending a `STOP_SENDING`
                // frame to prompt closure of the stream in the opposite direction.
                if !stream.recv.is_fin() {
                    self.mark_stopped(stream_id, true, err);
                }

                // Stream should not be readable if it is shutdown in the receive-side.
                self.mark_readable(stream_id, false);

                // When a stream's receive-side shutdown, all unread data will be
                // discarded, we consider them as consumed, which might trigger a
                // connection-level flow control update.
                self.flow_control.increase_read_off(unread_len);
                if self.flow_control.should_send_max_data() {
                    self.rx_almost_full = true;
                }
            }

            Shutdown::Write => {
                // Peer initiated uni stream should not be shutdown in the send-side.
                if !is_local(stream_id, is_server) && !is_bidi(stream_id) {
                    return Err(Error::StreamStateError);
                }

                let (final_size, unsent) = stream.send.shutdown()?;

                // Give back some flow control credit by deducting the data that
                // was buffered but not actually sent before the stream send-side
                // was shutdown.
                self.send_capacity.tx_data = self.send_capacity.tx_data.saturating_sub(unsent);

                // Update connection-level send capacity.
                self.send_capacity.update_capacity();

                self.mark_reset(stream_id, true, err, final_size);

                // Stream should not be writable after it is shutdown in the send-side.
                self.mark_writable(stream_id, false);
            }
        }

        Ok(())
    }

    /// Set priority for a stream.
    pub fn stream_set_priority(
        &mut self,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) -> Result<()> {
        // Get or create the stream if it was not created before.
        let stream = match self.get_or_create(stream_id, true) {
            Ok(v) => v,
            // Stream has been closed, just ignore the prioritization.
            Err(Error::Done) => return Ok(()),
            Err(e) => return Err(e),
        };

        if stream.urgency == urgency && stream.incremental == incremental {
            return Ok(());
        }

        stream.urgency = urgency;
        stream.incremental = incremental;

        Ok(())
    }

    /// Get the stream's send-side capacity, in units of bytes.
    /// The capacity is the minimum of the connection-level flow control credit
    /// and the stream-level flow control credit.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        match self.get(stream_id) {
            Some(s) => Ok(cmp::min(self.send_capacity.capacity, s.send.capacity()?)),
            None => Err(Error::StreamStateError),
        }
    }

    /// Return true if the stream has more than `len` bytes of send-side capacity.
    pub fn stream_writable(&mut self, stream_id: u64, len: usize) -> Result<bool> {
        if self.stream_capacity(stream_id)? >= len {
            return Ok(true);
        }

        // The connection-level flow control credit is not enough, mark the connection
        // blocked and schedule a DATA_BLOCKED frame to be sent to the peer.
        if self.max_tx_data_left() < len as u64 {
            self.update_data_blocked_at(Some(self.send_capacity.max_data));
        }

        // We have confirmed that the stream is existing when calling `stream_capacity`,
        // so it is safe to unwrap.
        let stream = self.get_mut(stream_id).unwrap();

        stream.write_thresh = cmp::max(1, len);

        let is_writable = stream.is_writable();

        // If the stream-level flow control credit is not enough, mark the stream
        // blocked and schedule a STREAM_DATA_BLOCKED frame to be sent to the peer.
        //
        // Note that we should mark the stream blocked at max_data, otherwise the
        // peer may ignore the STREAM_DATA_BLOCKED frame.
        if stream.send.capacity()? < len {
            let max_data = stream.send.max_data();
            if stream.send.blocked_at() != Some(max_data) {
                stream.send.update_blocked_at(Some(max_data));
                self.mark_blocked(stream_id, true, max_data);
            }
        } else if is_writable {
            self.mark_writable(stream_id, true);
        }

        Ok(false)
    }

    /// Return true if the stream has outstanding data to read.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        match self.get(stream_id) {
            Some(s) => s.is_readable(),
            None => false,
        }
    }

    /// Return true if the stream's receive-side final size is known, and the
    /// application has read all data from the stream.
    ///
    /// Note that this function also return true if the stream is reset by the peer.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        match self.get(stream_id) {
            Some(s) => s.recv.is_fin(),
            None => true,
        }
    }

    /// Set user context for a stream.
    pub fn stream_set_context<T: Any + Send + Sync>(
        &mut self,
        stream_id: u64,
        ctx: T,
    ) -> Result<()> {
        // Get or create the stream if it was not created before.
        let stream = match self.get_or_create(stream_id, true) {
            Ok(v) => v,
            Err(Error::Done) => return Ok(()), // stream closed
            Err(e) => return Err(e),
        };

        stream.context = Some(Box::new(ctx));
        Ok(())
    }

    /// Return the stream's user context.
    pub fn stream_context(&mut self, stream_id: u64) -> Option<&mut dyn Any> {
        if let Some(s) = self.get_mut(stream_id) {
            match s.context {
                Some(ref mut ctx) => Some(ctx.as_mut()),
                None => None,
            }
        } else {
            None
        }
    }

    /// Get the maximum amount of data that the stream can receive and sent.
    /// Return a tuple of (max_rx_data, max_tx_data).
    fn max_stream_data_limit(
        local: bool,
        bidi: bool,
        local_params: &StreamTransportParams,
        peer_params: &StreamTransportParams,
    ) -> (u64, u64) {
        // Based on the initiator(local/remote) and stream type(uni/bidi) to determine the
        // maximum amount of data that can be received and sent by the local endpoint.
        match (local, bidi) {
            // Local initiated bidirectional stream, can send and receive data.
            (true, true) => (
                local_params.initial_max_stream_data_bidi_local,
                peer_params.initial_max_stream_data_bidi_remote,
            ),

            // Local initiated unidirectional stream, can send data only.
            (true, false) => (0, peer_params.initial_max_stream_data_uni),

            // Peer initiated bidirectional stream, can receive and send data.
            (false, true) => (
                local_params.initial_max_stream_data_bidi_remote,
                peer_params.initial_max_stream_data_bidi_local,
            ),

            // Peer initiated unidirectional stream, can receive data only.
            (false, false) => (local_params.initial_max_stream_data_uni, 0),
        }
    }

    /// Return a mutable reference to the stream with the given ID if it exists,
    /// or create a new one with given paras otherwise if it is allowed.
    fn get_or_create(&mut self, id: u64, local: bool) -> Result<&mut Stream> {
        // A stream ID is a 62-bit integer (0 to 2^62-1) that is unique for all
        // streams on a connection.
        if id > crate::codec::VINT_MAX {
            return Err(Error::ProtocolViolation);
        }

        let closed = self.is_closed(id);
        match self.streams.entry(id) {
            // 1.Can not find any stream with the given stream ID.
            // It may not be created yet or it has been closed.
            hash_map::Entry::Vacant(v) => {
                // Stream has already been closed and collected into `closed`.
                if closed {
                    return Err(Error::Done);
                }

                // Requested stream ID is not valid with the current role.
                if local != is_local(id, self.is_server) {
                    return Err(Error::StreamStateError);
                }
                let bidi = is_bidi(id);

                // Get the maximum amount of data that the new stream can receive and sent.
                let (max_rx_data, max_tx_data) = Self::max_stream_data_limit(
                    local,
                    bidi,
                    &self.local_transport_params,
                    &self.peer_transport_params,
                );

                // Check if the stream ID complies with the stream limits of the current
                // role, and try to update the stream count if it is valid.
                self.concurrency_control
                    .check_concurrency_limits(id, self.is_server)?;

                // Create a new stream.
                let mut new_stream = Stream::new(
                    bidi,
                    local,
                    max_tx_data,
                    max_rx_data,
                    self.max_stream_window,
                );
                let trace_id = format!("{}-{}", &self.trace_id, id);
                new_stream.set_trace_id(&trace_id);

                // Stream might already be writable due to initial flow control credit.
                if new_stream.is_writable() {
                    self.writable.insert(id);
                }

                // Update stream id for next bidirectional/unidirectional stream.
                if bidi {
                    self.next_stream_id_bidi = cmp::max(self.next_stream_id_bidi, id);
                    self.next_stream_id_bidi = self.next_stream_id_bidi.saturating_add(4);
                } else {
                    self.next_stream_id_uni = cmp::max(self.next_stream_id_uni, id);
                    self.next_stream_id_uni = self.next_stream_id_uni.saturating_add(4);
                }

                self.concurrency_control.remove_avail_id(id, self.is_server);
                self.events.add(Event::StreamCreated(id));
                Ok(v.insert(new_stream))
            }

            // 2.Stream already exists.
            hash_map::Entry::Occupied(v) => Ok(v.into_mut()),
        }
    }

    /// Return true if we should send `MAX_DATA` frame to peer to update
    /// the connection level flow control limit.
    pub fn need_send_max_data(&self) -> bool {
        self.rx_almost_full && self.max_rx_data() < self.max_rx_data_next()
    }

    /// Return true if need to send stream frames.
    pub fn need_send_stream_frames(&self) -> bool {
        self.has_sendable_streams()
            || self.need_send_max_data()
            || self.data_blocked_at().is_some()
            || self.should_send_max_streams()
            || self.has_almost_full_streams()
            || self.has_blocked_streams()
            || self.has_reset_streams()
            || self.has_stopped_streams()
            || self.streams_blocked()
    }

    /// Push the stream ID to the sendable queue with the given urgency and
    /// incremental flag.
    ///
    /// If the given stream ID is already in the queue, this function must
    /// not be called to ensure the fairness of the scheduling and avoid the
    /// spurious cycles through the queue.
    fn push_sendable(&mut self, stream_id: u64, urgency: u8, incremental: bool) {
        // 1.Get priority queue with the given urgency, if it does not exist, create a new one.
        let queue = match self.sendable.entry(urgency) {
            btree_map::Entry::Vacant(v) => v.insert(StreamPriorityQueue::default()),
            btree_map::Entry::Occupied(v) => v.into_mut(),
        };

        // 2.Push the element to the queue corresponding to the given incremental flag.
        if !incremental {
            // Non-incremental streams are scheduled in order of their stream ID.
            queue.non_incremental.push(cmp::Reverse(stream_id))
        } else {
            // Incremental streams are scheduled in a round-robin fashion.
            queue.incremental.push_back(stream_id)
        };
    }

    /// Return the first stream ID from the sendable queue with the highest priority.
    ///
    /// Note that the caller should call `remove_sendable` to remove the stream from the
    /// queue if it is no longer sendable after sending some of its outstanding data.
    pub fn peek_sendable(&mut self) -> Option<u64> {
        let queue = match self.sendable.iter_mut().next() {
            Some((_, queue)) => queue,
            None => return None,
        };

        // 1.Try to get the non-incremental stream with the lowest stream ID.
        match queue.non_incremental.peek().map(|x| x.0) {
            Some(stream_id) => Some(stream_id),
            None => {
                // 2.Try to get the incremental stream from the front of the queue.
                // Incremental streams are scheduled in a round-robin fashion, So
                // we should move the current peeked incremental stream to the end
                // of the queue.
                match queue.incremental.pop_front() {
                    Some(stream_id) => {
                        queue.incremental.push_back(stream_id);
                        Some(stream_id)
                    }
                    // Should never happen.
                    None => None,
                }
            }
        }
    }

    /// Remove the last peeked stream from the sendable streams queue.
    pub fn remove_sendable(&mut self) {
        // Get the first entry which is the queue with the highest priority.
        let mut entry = match self.sendable.first_entry() {
            Some(entry) => entry,
            // Should never happen, as `peek_sendable()` must be called priorly.
            None => return,
        };

        let queue = entry.get_mut();
        queue
            .non_incremental
            .pop()
            .map(|x| x.0)
            .or_else(|| queue.incremental.pop_back());

        // Remove the queue from the queues list if it is empty at present time,
        // so that the next time `peek_sendable()` is invoked, the next non-empty
        // queue is selected.
        if queue.non_incremental.is_empty() && queue.incremental.is_empty() {
            entry.remove();
        }
    }

    /// Add or remove the stream ID to/from the `readable` streams set.
    ///
    /// Do nothing if `readable` is true but the stream was already in the list.
    fn mark_readable(&mut self, stream_id: u64, readable: bool) {
        match readable {
            true => self.readable.insert(stream_id),
            false => self.readable.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `writable` streams set.
    ///
    /// Do nothing if `writable` is true but the stream was already in the list.
    fn mark_writable(&mut self, stream_id: u64, writable: bool) {
        match writable {
            true => self.writable.insert(stream_id),
            false => self.writable.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `almost_full` streams set.
    ///
    /// Do nothing if `almost_full` is true but the stream was already in the list.
    pub fn mark_almost_full(&mut self, stream_id: u64, almost_full: bool) {
        match almost_full {
            true => self.almost_full.insert(stream_id),
            false => self.almost_full.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `data_blocked` streams set with the
    /// given offset value.
    ///
    /// If `blocked` is true but the stream was already in the list, the offset value
    /// will be updated.
    pub fn mark_blocked(&mut self, stream_id: u64, blocked: bool, off: u64) {
        match blocked {
            true => self.data_blocked.insert(stream_id, off),
            false => self.data_blocked.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `reset` streams set with the
    /// given error code and final size values.
    ///
    /// If `reset` is true but the stream was already in the list, the error code
    /// and final size values will be updated.
    pub fn mark_reset(&mut self, stream_id: u64, reset: bool, error_code: u64, final_size: u64) {
        match reset {
            true => self.reset.insert(stream_id, (error_code, final_size)),
            false => self.reset.remove(&stream_id),
        };
    }

    /// Add or remove the stream ID to/from the `stop` streams set with the
    /// given error code.
    ///
    /// If `stopped` is true but the stream was already in the list, the error code
    /// will be updated.
    pub fn mark_stopped(&mut self, stream_id: u64, stopped: bool, error_code: u64) {
        match stopped {
            true => self.stopped.insert(stream_id, error_code),
            false => self.stopped.remove(&stream_id),
        };
    }

    /// Remove the stream ID from the readable and writable streams sets, and
    /// adds it to the closed streams set.
    ///
    /// Note that this method does not check if the stream id is complied with
    /// the role of the endpoint.
    fn mark_closed(&mut self, stream_id: u64, local: bool) {
        if self.is_closed(stream_id) {
            return;
        }

        // Give back a max_streams credit if the stream was initiated by the peer.
        if !local {
            if is_bidi(stream_id) {
                self.concurrency_control
                    .increase_max_streams_credits(true, 1);
            } else {
                self.concurrency_control
                    .increase_max_streams_credits(false, 1);
            }
        }

        self.mark_readable(stream_id, false);
        self.mark_writable(stream_id, false);
        if let Some(stream) = self.get_mut(stream_id) {
            stream.mark_closed();
        }
        #[cfg(test)]
        self.closed.insert(stream_id);

        if self.events.add(Event::StreamClosed(stream_id)) {
            // When event queue is enabled, inform the Endpoint to process
            // StreamClosed event and destroy the stream object.
            return;
        }
        self.stream_destroy(stream_id);
    }

    /// Destroy the closed stream.
    pub(crate) fn stream_destroy(&mut self, stream_id: u64) {
        self.streams.remove(&stream_id);
    }

    /// Get the maximum streams that the peer allows the local endpoint to open.
    pub fn peer_max_streams(&self, bidi: bool) -> u64 {
        self.concurrency_control.peer_max_streams(bidi)
    }

    /// After sending a MAX_STREAMS(type: 0x12..0x13) frame, update local max_streams limit.
    pub fn update_local_max_streams(&mut self, bidi: bool) {
        self.concurrency_control.update_local_max_streams(bidi);
    }

    /// Get the maximum streams that the local endpoint allow the peer to open.
    pub fn max_streams(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.concurrency_control.local_max_streams_bidi,
            false => self.concurrency_control.local_max_streams_uni,
        }
    }

    /// Get the next max streams limit that will be sent to the peer
    /// in a MAX_STREAMS(type:0x12..0x13) frame.
    pub fn max_streams_next(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.concurrency_control.local_max_streams_bidi_next,
            false => self.concurrency_control.local_max_streams_uni_next,
        }
    }

    /// Return true if we should send a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    pub fn should_send_max_streams(&self) -> bool {
        self.concurrency_control
            .should_update_local_max_streams(true)
            || self
                .concurrency_control
                .should_update_local_max_streams(false)
    }

    /// Return true if the max streams limit should be updated
    /// by sending a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    pub fn should_update_local_max_streams(&self, bidi: bool) -> bool {
        self.concurrency_control
            .should_update_local_max_streams(bidi)
    }

    /// Get the last offset at which the connection send-side was blocked, if any.
    pub fn data_blocked_at(&self) -> Option<u64> {
        self.send_capacity.blocked_at
    }

    pub fn streams_blocked(&self) -> bool {
        self.concurrency_control.streams_blocked_at_bidi.is_some()
            || self.concurrency_control.streams_blocked_at_uni.is_some()
    }

    pub fn streams_blocked_at(&self, bidi: bool) -> Option<u64> {
        match bidi {
            true => self.concurrency_control.streams_blocked_at_bidi,
            false => self.concurrency_control.streams_blocked_at_uni,
        }
    }

    /// Return an iterator over all the existing streams.
    pub fn iter(&self) -> StreamIter {
        StreamIter {
            streams: self.streams.keys().copied().collect(),
        }
    }

    /// Return an iterator over streams that have outstanding data to be read
    /// by the application.
    pub fn readable_iter(&self) -> StreamIter {
        StreamIter::from(&self.readable)
    }

    /// Return true if there are any streams that have data to read.
    pub fn has_readable(&self) -> bool {
        let iter = StreamIter::from(&self.readable);
        for stream_id in iter {
            if self.check_readable(stream_id) {
                trace!("{} has readable stream {}", self.trace_id, stream_id);
                return true;
            }
        }

        trace!("{} no any readable stream", self.trace_id);
        false
    }

    /// Return an iterator over streams that have available send capacity of stream level.
    pub fn writable_iter(&self) -> StreamIter {
        StreamIter::from(&self.writable)
    }

    /// Return true if there are any streams that can be written by the application.
    pub fn has_writable(&self) -> bool {
        if self.send_capacity.capacity == 0 {
            return false;
        }

        let iter = StreamIter::from(&self.writable);
        for stream_id in iter {
            if self.check_writable(stream_id) {
                trace!("{} has writable stream {}", self.trace_id, stream_id);
                return true;
            }
        }

        trace!("{} no any writable stream", self.trace_id);
        false
    }

    /// Set want write flag for a stream.
    ///
    /// Return `Error::Done` if the stream is not found.
    pub fn want_write(&mut self, stream_id: u64, want: bool) -> Result<()> {
        match self.get_mut(stream_id) {
            Some(stream) => stream.mark_wantwrite(want),
            None => Err(Error::Done),
        }
    }

    /// Set want read flag for a stream.
    ///
    /// Return `Error::Done` if the stream is not found.
    pub fn want_read(&mut self, stream_id: u64, want: bool) -> Result<()> {
        match self.get_mut(stream_id) {
            Some(stream) => stream.mark_wantread(want),
            None => Err(Error::Done),
        }
    }

    /// Return true if application wants to write more data to the stream
    /// and it has enough flow control capacity to do so.
    ///
    /// Note that if application wants to write, and the stream was stopped
    /// by peer, return true.
    pub fn check_writable(&self, stream_id: u64) -> bool {
        if let Some(stream) = self.get(stream_id) {
            if !stream.is_wantwrite() {
                return false;
            }

            let capacity = match stream.send.capacity() {
                Ok(v) => v,

                // If stream.send.capacity() return err, it means the stream is stopped
                // by peer, then we return the stream to the application immediately.
                Err(_) => return true,
            };

            if cmp::min(self.send_capacity.capacity, capacity) >= stream.write_thresh {
                return true;
            }
        }

        false
    }

    /// Return true if application wants to read more data from the stream.
    pub fn check_readable(&self, stream_id: u64) -> bool {
        if let Some(stream) = self.get(stream_id) {
            return stream.is_wantread();
        }

        false
    }

    /// Return an iterator over streams that the available send capacity can be used
    /// by the peer are almost full, and need to send MAX_STREAM_DATA to the peer.
    pub fn almost_full(&self) -> StreamIter {
        StreamIter::from(&self.almost_full)
    }

    /// Return an iterator over streams that wish to send data but are unable to do so
    /// due to stream-level flow control and need to send STREAM_DATA_BLOCKED to the peer.
    pub fn blocked(&self) -> hash_map::Iter<u64, u64> {
        self.data_blocked.iter()
    }

    /// Create an iterator over streams that the send-side has been shutdown
    /// prematurely and need to send RESET_STREAM frame to the peer.
    pub fn reset(&self) -> hash_map::Iter<u64, (u64, u64)> {
        self.reset.iter()
    }

    /// Create an iterator over streams that the receive-side has been shutdown
    /// prematurely and need to send STOP_SENDING frame to the peer.
    pub fn stopped(&self) -> hash_map::Iter<u64, u64> {
        self.stopped.iter()
    }

    /// Return true if the stream has been closed.
    pub fn is_closed(&self, stream_id: u64) -> bool {
        // It is an existing stream
        if let Some(stream) = self.get(stream_id) {
            return stream.is_closed();
        }

        // It is a stream to be create
        let is_server = self.is_server;
        if self.concurrency_control.is_available(stream_id, is_server)
            || self.concurrency_control.is_limited(stream_id, is_server)
        {
            return false;
        }

        // It is a destroyed stream
        true
    }

    /// Return true if there are any streams that have buffered data to send.
    fn has_sendable_streams(&self) -> bool {
        !self.sendable.is_empty()
    }

    /// Return true if there are any streams that have data to be read by application.
    pub fn has_readable_streams(&self) -> bool {
        !self.readable.is_empty()
    }

    /// Return true if there are any streams that need to send MAX_STREAM_DATA
    /// to update the receive-side flow control limit.
    fn has_almost_full_streams(&self) -> bool {
        !self.almost_full.is_empty()
    }

    /// Return true if there are any streams that wish to send data but are unable
    /// to do so due to stream-level flow control and need to send STREAM_DATA_BLOCKED
    /// frame to the peer.
    fn has_blocked_streams(&self) -> bool {
        !self.data_blocked.is_empty()
    }

    /// Return true if there are any streams that are reset in the send-side
    /// and need to send RESET_STREAM frame to the peer.
    fn has_reset_streams(&self) -> bool {
        !self.reset.is_empty()
    }

    /// Return true if there are any streams that are shutdown on the receive-side
    /// and need to send STOP_SENDING frame to the peer.
    fn has_stopped_streams(&self) -> bool {
        !self.stopped.is_empty()
    }

    /// Update connection send-side flow control blocked state.
    pub fn update_data_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.send_capacity.update_blocked_at(blocked_at);
    }

    /// Update connection concurrency control blocked state.
    pub fn update_streams_blocked_at(&mut self, bidi: bool, blocked_at: Option<u64>) {
        self.concurrency_control
            .update_streams_blocked_at(bidi, blocked_at);
    }

    /// Receive a MAX_DATA frame from the peer, update the connection-level
    /// send-side flow control limit.
    pub fn on_max_data_frame_received(&mut self, max_data: u64) {
        self.send_capacity.update_max_data(max_data);
        self.send_capacity.update_capacity();

        // Cancel the connection-level flow control blocked state if the
        // connection-level flow control limit is increased, avoid sending
        // redundant DATA_BLOCKED frames.
        if Some(self.send_capacity.max_data) > self.send_capacity.blocked_at {
            self.send_capacity.blocked_at = None;
        }
    }

    /// Receive a MAX_STREAM_DATA frame from the peer, update the stream-level
    /// send-side flow control limit.
    pub fn on_max_stream_data_frame_received(
        &mut self,
        stream_id: u64,
        max_data: u64,
    ) -> Result<()> {
        // RFC9000 19.10. MAX_STREAM_DATA Frames
        // An endpoint that receives a MAX_STREAM_DATA frame for a receive-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        let was_sendable = stream.is_sendable();

        stream.send.update_max_data(max_data);

        // Note that we don't need to check and update the stream-level flow control
        // blocked state here, it will be checked and updated in stream_send.

        let writable = stream.is_writable();

        // If the stream is now sendable push it to the sendable queue,
        // but only if it wasn't already queued.
        if stream.is_sendable() && !was_sendable {
            // Note: rust borrow checker doesn't allow us to borrow `self` twice,
            // so here we cannot use stream.urgency and stream.incremental directly.
            let urgency = stream.urgency;
            let incremental = stream.incremental;
            self.push_sendable(stream_id, urgency, incremental);
        }

        if writable {
            self.mark_writable(stream_id, true);
        }

        Ok(())
    }

    /// Receive a MAX_STREAMS frame from the peer, update the max stream limits.
    pub fn on_max_streams_frame_received(&mut self, max_streams: u64, bidi: bool) -> Result<()> {
        // RFC9000 19.11. MAX_STREAMS Frames
        // A count of the cumulative number of streams of the corresponding
        // type that can be opened over the lifetime of the connection.
        // This value cannot exceed 2^60, as it is not possible to encode
        // stream IDs larger than 2^62-1. Receipt of a frame that permits
        // opening of a stream larger than this limit MUST be treated as
        // a connection error of type FRAME_ENCODING_ERROR.
        if max_streams > MAX_STREAMS_PER_TYPE {
            return Err(Error::FrameEncodingError);
        }

        self.concurrency_control
            .update_peer_max_streams(bidi, max_streams);

        Ok(())
    }

    /// Receive a DATA_BLOCKED frame from the peer.
    pub fn on_data_blocked_frame_received(&mut self, max_data: u64) {
        // We will judge whether to send MAX_DATA frame actively according to the received
        // data, and do not rely on the DATA_BLOCKED frame from the peer.
    }

    /// Receive a STREAM_DATA_BLOCKED frame from the peer.
    pub fn on_stream_data_blocked_frame_received(
        &mut self,
        stream_id: u64,
        max_stream_data: u64,
    ) -> Result<()> {
        // RFC9000 19.13. STREAM_DATA_BLOCKED Frames
        // An endpoint that receives a STREAM_DATA_BLOCKED frame for a send-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        Ok(())
    }

    /// Receive a STREAMS_BLOCKED frame from the peer.
    pub fn on_streams_blocked_frame_received(
        &mut self,
        max_streams: u64,
        bidi: bool,
    ) -> Result<()> {
        if max_streams > MAX_STREAMS_PER_TYPE {
            return Err(Error::FrameEncodingError);
        }

        Ok(())
    }

    /// Receive a RESET_STREAM frame from the peer.
    pub fn on_reset_stream_frame_received(
        &mut self,
        stream_id: u64,
        error_code: u64,
        final_size: u64,
    ) -> Result<()> {
        // Peer can't send data on local initialized unidirectional streams.
        // RFC9000 19.4. RESET_STREAM Frame
        // An endpoint that receives a RESET_STREAM frame for a send-only stream
        // MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_bidi(stream_id) && is_local(stream_id, self.is_server) {
            return Err(Error::StreamStateError);
        }

        // Note: We cannot move this line to after calling get_or_create() because
        // borrow `*self` as immutable after it is borrowed as mutable was forbidden.
        let max_rx_data_left = self.max_rx_data_left();

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if !stream.recv.is_complete() {
            warn!("{} received RESET_STREAM frame before recv completed with error code {} and final size {}, recv_off {} read_off {}",
                stream.trace_id, error_code, final_size, stream.recv.recv_off, stream.recv.read_off);
        } else {
            trace!(
                "{} received RESET_STREAM frame with error code {} and final size {}",
                stream.trace_id,
                error_code,
                final_size
            );
        }

        let was_readable = stream.is_readable();

        // When a stream is reset, all buffered data will be discarded, so consider
        // the received data as consumed, which might trigger a connection-level
        // flow control update.
        let max_fc_off_delta = final_size.saturating_sub(stream.recv.read_off());

        let max_rx_off_delta = stream.recv.reset(error_code, final_size)? as u64;

        if max_rx_off_delta > max_rx_data_left {
            return Err(Error::FlowControlError);
        }

        let is_readable = stream.is_readable();
        let is_complete = stream.is_complete();
        let local = stream.local;

        if !was_readable && is_readable {
            self.mark_readable(stream_id, true);
        }

        // Mark closed if the stream is complete and not readable.
        if is_complete && !is_readable {
            self.mark_closed(stream_id, local);
        }

        self.flow_control.increase_recv_off(max_rx_off_delta);
        self.flow_control.increase_read_off(max_fc_off_delta);
        if self.flow_control.should_send_max_data() {
            self.rx_almost_full = true;
        }

        Ok(())
    }

    /// Receive a STOP_SENDING frame from the peer.
    pub fn on_stop_sending_frame_received(
        &mut self,
        stream_id: u64,
        error_code: u64,
    ) -> Result<()> {
        // RFC9000 19.5. STOP_SENDING Frames
        // An endpoint that receives a STOP_SENDING frame for a receive-only
        // stream MUST terminate the connection with error STREAM_STATE_ERROR.
        if !is_local(stream_id, self.is_server) && !is_bidi(stream_id) {
            return Err(Error::StreamStateError);
        }

        // Note that the following rule is implemented in get_or_create().
        // Receiving a STOP_SENDING frame for a locally initiated stream that
        // has not yet been created MUST be treated as a connection error of
        // type STREAM_STATE_ERROR.

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        if !stream.send.is_complete() {
            warn!("{} received STOP_SENDING frame before send completed with error code {}, write_off {} unsent_off {} unacked_len {}",
                stream.trace_id, error_code, stream.send.write_off, stream.send.unsent_off, stream.send.unacked_len);
        } else {
            trace!(
                "{} received STOP_SENDING frame with error code {}",
                stream.trace_id,
                error_code
            );
        }

        let was_writable = stream.is_writable();

        if let Ok((final_size, unsent)) = stream.send.stop(error_code) {
            // Claw back some flow control allowance from data that was
            // buffered but not actually sent before the stream was
            // reset.
            self.send_capacity.tx_data = self.send_capacity.tx_data.saturating_sub(unsent);
            self.send_capacity.update_capacity();

            // RFC9000 3.5
            //   A STOP_SENDING frame requests that the receiving endpoint send a RESET_STREAM frame.
            // An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame if the
            // stream is in the "Ready" or "Send" state. If the stream is in the "Data Sent" state,
            // the endpoint MAY defer sending the RESET_STREAM frame until the packets containing
            // outstanding data are acknowledged or declared lost. If any outstanding data is declared
            // lost, the endpoint SHOULD send a RESET_STREAM frame instead of retransmitting the data.
            //   An endpoint SHOULD copy the error code from the STOP_SENDING frame to the RESET_STREAM
            // frame it sends, but it can use any application error code. An endpoint that sends a
            // STOP_SENDING frame MAY ignore the error code in any RESET_STREAM frames subsequently
            // received for that stream.
            self.mark_reset(stream_id, true, error_code, final_size);

            if !was_writable {
                self.mark_writable(stream_id, true);
            }
        }
        Ok(())
    }

    /// Autotune the connection's receive-side flow control window size.
    pub fn autotune_window(&mut self, now: time::Instant, srtt: time::Duration) {
        self.flow_control.autotune_window(now, srtt);
    }

    /// Get the connection's receive-side flow control limit.
    pub fn max_rx_data(&self) -> u64 {
        self.flow_control.max_data()
    }

    /// Get the connection's receive-side next flow control limit that will be
    /// sent to the peer in a MAX_DATA frame.
    pub fn max_rx_data_next(&self) -> u64 {
        self.flow_control.max_data_next()
    }

    /// Apply the connection's receive-side new flow control limit.
    pub fn update_max_rx_data(&mut self, now: Instant) {
        self.flow_control.update_max_data(now);
    }

    /// Ensure that the connection flow control window always has some room
    /// compared to the stream flow control window.
    pub fn ensure_window_lower_bound(&mut self, min_window: u64) {
        self.flow_control.ensure_window_lower_bound(min_window);
    }

    /// Get the connection's receive-side flow control capacity remaining.
    fn max_rx_data_left(&self) -> u64 {
        self.flow_control.max_data() - self.flow_control.recv_off()
    }

    /// Get the connection's send-side flow control capacity remaining.
    fn max_tx_data_left(&self) -> u64 {
        self.send_capacity.max_data - self.send_capacity.tx_data
    }

    /// Get the largest offset observed on current connection.
    #[cfg(test)]
    fn max_recv_off(&self) -> u64 {
        self.flow_control.recv_off()
    }

    /// Get the connection's send-side flow control limit.
    #[cfg(test)]
    fn max_tx_data(&self) -> u64 {
        self.send_capacity.max_data
    }

    /// Get the total amount of data sent on the entire connection.
    #[cfg(test)]
    fn tx_data(&self) -> u64 {
        self.send_capacity.tx_data
    }

    /// Get the connection's send-side flow control capacity remaining.
    #[cfg(test)]
    fn tx_capacity(&self) -> usize {
        self.send_capacity.capacity
    }

    /// Receive a STREAM frame from the peer.
    pub fn on_stream_frame_received(
        &mut self,
        stream_id: u64,
        offset: u64,
        length: usize,
        fin: bool,
        data: Bytes,
    ) -> Result<()> {
        // RFC9000 19.8. STREAM Frames
        // An endpoint MUST terminate the connection with error STREAM_STATE_ERROR
        // if it receives a STREAM frame for a locally initiated stream that has not
        // yet been created, or for a send-only stream.
        if is_local(stream_id, self.is_server) {
            // Recv STREAM frame on a locally initiated uni stream.
            if !is_bidi(stream_id)
            // Recv STREAM frame on a stream that has not yet been created.
            || (self.get(stream_id).is_none() && !self.is_closed(stream_id))
            {
                return Err(Error::StreamStateError);
            }
        }

        // Note: We cannot move this line to after calling get_or_create() because
        // borrow `*self` as immutable after it is borrowed as mutable was forbidden.
        let max_rx_data_left = self.max_rx_data_left();

        // Get existing stream or create a new one, but if the stream
        // has already been closed and collected, ignore the frame.
        let stream = match self.get_or_create(stream_id, false) {
            Ok(v) => v,

            // Stream is already closed, just ignore the frame even though
            // it might be illegal.
            Err(Error::Done) => return Ok(()),

            Err(e) => return Err(e),
        };

        let data_max_off = offset + length as u64;

        // Check for the connection-level flow control limit.
        let max_rx_off_delta = data_max_off.saturating_sub(stream.recv.recv_off());
        if max_rx_off_delta > max_rx_data_left {
            return Err(Error::FlowControlError);
        }

        let was_readable = stream.is_readable();
        let was_draining = stream.is_draining();

        // Insert the new data into the stream's receive buffer.
        stream.recv.write(offset, data, fin)?;

        if !was_readable && stream.is_readable() {
            self.mark_readable(stream_id, true);
        }

        self.flow_control.increase_recv_off(max_rx_off_delta);

        if was_draining {
            // We won't buffer incoming data any more after the stream's receive-side
            // shutdown, but consider the received data as consumed, and try to update
            // the connection-level flow control limit.
            self.flow_control.increase_read_off(max_rx_off_delta);
            if self.flow_control.should_send_max_data() {
                self.rx_almost_full = true;
            }
        }

        Ok(())
    }

    /// STREAM frame was acked, release data block from send buffer, and
    /// delete stream from streams set if it's complete and not readable.
    pub fn on_stream_frame_acked(&mut self, stream_id: u64, offset: u64, length: usize) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        stream.send.ack_and_drop(offset, length);

        // Mark closed if the stream is complete and not readable.
        if stream.is_complete() && !stream.is_readable() {
            let local = stream.local;
            self.mark_closed(stream_id, local);
        }
    }

    /// RESET_STREAM frame was acked, the sending part of the stream enters
    /// the "Reset Recvd" state, which is a terminal state. If the receiving
    /// part of the stream is already in a terminal state, delete the stream
    /// from streams set.
    pub fn on_reset_stream_frame_acked(&mut self, stream_id: u64) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        // Mark closed if the stream is complete and not readable.
        if stream.is_complete() && !stream.is_readable() {
            let local = stream.local;
            self.mark_closed(stream_id, local);
        }
    }

    /// STREAM frame was lost, mark data block should be retransmitted and
    /// try add stream to priority queue.
    pub fn on_stream_frame_lost(&mut self, stream_id: u64, offset: u64, length: usize, fin: bool) {
        let stream = match self.streams.get_mut(&stream_id) {
            Some(v) => v,
            None => return,
        };

        let was_sendable = stream.is_sendable();
        let empty_fin = length == 0 && fin;

        // Mark data block should be retransmitted.
        stream.send.retransmit(offset, length);

        // Add stream to priority queue if the stream is now sendable and
        // it wasn't already queued.
        // Note that the stream may only has a zero-length frame with fin flag.
        if (stream.is_sendable() || empty_fin) && !was_sendable {
            let urgency = stream.urgency;
            let incremental = stream.incremental;
            self.push_sendable(stream_id, urgency, incremental);
        }
    }

    /// RESET_STREAM frame was lost, if the stream is still open, add the stream
    /// to the reset set to ensure a RESET_STREAM frame will be retransmitted.
    pub fn on_reset_stream_frame_lost(&mut self, stream_id: u64, error_code: u64, final_size: u64) {
        if self.streams.contains_key(&stream_id) {
            self.mark_reset(stream_id, true, error_code, final_size);
        }
    }

    /// STOP_SENDING frame was lost, add the stream to the stopped set to ensure
    /// a STOP_SENDING frame will be sent unless the stream receive-side is finished.
    pub fn on_stop_sending_frame_lost(&mut self, stream_id: u64, error_code: u64) {
        let stream = match self.streams.get(&stream_id) {
            Some(v) => v,
            None => return,
        };

        // Receive-side final size is known, do not retransmit STOP_SENDING frame.
        if !stream.recv.is_fin() {
            self.mark_stopped(stream_id, true, error_code);
        }
    }

    /// MAX_STREAM_DATA frame was lost, add the stream to the almost full set
    /// to ensure a MAX_STREAM_DATA frame will be sent.
    pub fn on_max_stream_data_frame_lost(&mut self, stream_id: u64) {
        if self.streams.contains_key(&stream_id) {
            self.mark_almost_full(stream_id, true);
        }
    }

    /// MAX_DATA frame was lost, mark the receive-side flow control of the
    /// connection is almost full to ensure a MAX_DATA frame will be sent.
    pub fn on_max_data_frame_lost(&mut self) {
        self.rx_almost_full = true;
    }

    /// MAX_STREAMS frame was lost.
    pub fn on_max_streams_frame_lost(&mut self, bidi: bool, max: u64) {
        // We will send MAX_STREAMS frames to update the max_streams limit according to
        // the stream consumption situation actively, but we will not retransmit the lost
        // MAX_STREAMS frames. If multiple MAX_STREAMS frames are lost continuously, it
        // may cause the max_streams limit perceived by the peer to be smaller than the
        // max_streams limit we set. At this time, the peer should process according to
        // the max_streams limit specified in the protocol.
    }

    /// STREAM_DATA_BLOCKED frame was lost, if peer still not issue more
    /// max_stream_data credits, mark stream data blocked again to ensure
    /// a STREAM_DATA_BLOCKED frame will be sent.
    pub fn on_stream_data_blocked_frame_lost(&mut self, stream_id: u64, blocked_at: u64) {
        let stream = match self.streams.get(&stream_id) {
            Some(v) => v,
            None => return,
        };

        if blocked_at == stream.send.max_data {
            self.mark_blocked(stream_id, true, blocked_at);
        }
    }

    /// DATA_BLOCKED frame was lost, if peer still not issue more max_data credits,
    /// mark data blocked again to ensure a DATA_BLOCKED frame will be sent.
    pub fn on_data_blocked_frame_lost(&mut self, max: u64) {
        if max == self.send_capacity.max_data {
            self.update_data_blocked_at(Some(max));
        }
    }

    /// STREAMS_BLOCKED frame was lost, if peer still not issue more max_streams credits,
    /// mark streams blocked again to ensure a STREAMS_BLOCKED frame will be sent.
    pub fn on_streams_blocked_frame_lost(&mut self, bidi: bool, max_streams: u64) {
        if max_streams == self.concurrency_control.peer_max_streams(bidi) {
            self.concurrency_control
                .update_streams_blocked_at(bidi, Some(max_streams));
        }
    }

    /// Get the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }

    /// Update the peer transport parameters after receiving them from the peer.
    pub fn update_peer_stream_transport_params(&mut self, tp: StreamTransportParams) {
        self.peer_transport_params = tp;

        // Update the peer's max data and local's send capacity for
        // connection-level send-side flow control.
        self.send_capacity.update_max_data(tp.initial_max_data);
        self.send_capacity.update_capacity();

        // Update the peer's max streams limit for concurrency control.
        self.concurrency_control
            .update_peer_max_streams(true, tp.initial_max_streams_bidi);
        self.concurrency_control
            .update_peer_max_streams(false, tp.initial_max_streams_uni);
    }
}
