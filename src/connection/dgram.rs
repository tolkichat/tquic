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

//! Datagram operations for QUIC connections (RFC 9221).

use super::*;

impl Connection {
    /// Receive an incoming datagram from the peer.
    ///
    /// Returns the datagram payload, or `Error::Done` when the receive
    /// queue is empty. Datagrams are delivered in FIFO order.
    pub fn dgram_recv(&mut self) -> Result<Bytes> {
        self.dgram_recv_queue.pop_front().ok_or(Error::Done)
    }

    /// Return `true` if there are datagrams waiting to be read.
    pub fn dgram_readable(&self) -> bool {
        !self.dgram_recv_queue.is_empty()
    }

    /// Queue a datagram for sending to the peer.
    ///
    /// Returns `Error::InvalidState` if the peer has not advertised
    /// datagram support. Returns `Error::BufferTooShort` if the
    /// payload exceeds the peer's `max_datagram_frame_size` limit.
    pub fn dgram_send(&mut self, data: Bytes) -> Result<()> {
        let peer_max =
            self.peer_transport_params
                .max_datagram_frame_size
                .ok_or(Error::InvalidState(
                    "peer does not support datagrams".into(),
                ))?;
        let wire = 1 + codec::encode_varint_len(data.len() as u64) + data.len();
        if wire > peer_max as usize {
            return Err(Error::BufferTooShort);
        }
        if self.dgram_send_queue.len() >= 128 {
            // Drop oldest to make room (tail-drop).
            self.dgram_send_queue.pop_front();
        }
        self.dgram_send_queue.push_back(data);
        self.mark_tickable(true);
        Ok(())
    }

    /// Return the maximum datagram payload size the peer will accept,
    /// or `None` if the peer has not advertised datagram support.
    ///
    /// The peer's `max_datagram_frame_size` includes frame overhead
    /// (1 byte type + varint length), so we subtract that here.
    pub fn dgram_max_payload_size(&self) -> Option<usize> {
        self.peer_transport_params
            .max_datagram_frame_size
            .map(|frame_max| {
                let max = frame_max as usize;
                // Overhead: 1 byte frame type (0x31) + varint-encoded payload length.
                // Use (max - 1) as upper bound for the payload length varint.
                let overhead = 1 + codec::encode_varint_len(max.saturating_sub(1) as u64);
                max.saturating_sub(overhead)
            })
    }

    /// Return `true` if datagrams can be sent (peer supports them and
    /// the send queue is not full).
    pub fn dgram_sendable(&self) -> bool {
        self.peer_transport_params.max_datagram_frame_size.is_some()
            && self.dgram_send_queue.len() < 128
    }
}
