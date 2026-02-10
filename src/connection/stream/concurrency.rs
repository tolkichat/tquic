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
use std::collections::BinaryHeap;
use std::collections::VecDeque;
use std::ops::Range;

use super::stream_state::is_bidi;
use super::stream_state::is_local;
use crate::ranges;
use crate::Error;
use crate::Result;

/// Concurrency control for streams.
/// RFC9000 4.6 Controlling Concurrency
/// https://www.rfc-editor.org/rfc/rfc9000.html#name-controlling-concurrency
#[derive(Clone, Debug, PartialEq, Default)]
pub(crate) struct ConcurrencyControl {
    /// Maximum bidirectional streams that the peer allow local endpoint to open.
    pub(super) peer_max_streams_bidi: u64,

    /// Maximum unidirectional streams that the peer allow local endpoint to open.
    pub(super) peer_max_streams_uni: u64,

    /// The total number of bidirectional streams opened by the peer.
    pub(super) peer_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the peer.
    pub(super) peer_opened_streams_uni: u64,

    /// Maximum bidirectional streams that the local endpoint allow the peer to open.
    pub(super) local_max_streams_bidi: u64,
    /// The next MAX_STREAMS(type 0x12) limit for bidirectional streams
    pub(super) local_max_streams_bidi_next: u64,

    /// Maximum unidirectional streams that the local endpoint allow the peer to open.
    pub(super) local_max_streams_uni: u64,
    /// The next MAX_STREAMS(type 0x13) limit for unidirectional streams
    pub(super) local_max_streams_uni_next: u64,

    /// The total number of bidirectional streams opened by the local endpoint.
    pub(super) local_opened_streams_bidi: u64,

    /// The total number of unidirectional streams opened by the local endpoint.
    pub(super) local_opened_streams_uni: u64,

    /// Local endpoint want to open more bidirectional streams, but blocked by
    /// peer's concurrency control limit, we need to send a STREAMS_BLOCKED(type 0x16)
    /// frame to notify peer.
    pub(super) streams_blocked_at_bidi: Option<u64>,

    /// Local endpoint want to open more unidirectional streams, but blocked by
    /// peer's concurrency control limit, we need to send a STREAMS_BLOCKED(type 0x17)
    /// frame to notify peer.
    pub(super) streams_blocked_at_uni: Option<u64>,

    /// Available stream ids for peer initiated bidirectional streams.
    pub(super) peer_bidi_avail_ids: ranges::RangeSet,

    /// Available stream ids for peer initiated unidirectional streams.
    pub(super) peer_uni_avail_ids: ranges::RangeSet,

    /// Available stream ids for local initiated bidirectional streams.
    pub(super) local_bidi_avail_ids: ranges::RangeSet,

    /// Available stream ids for local initiated unidirectional streams.
    pub(super) local_uni_avail_ids: ranges::RangeSet,
}

impl ConcurrencyControl {
    pub(super) fn new(
        local_max_streams_bidi: u64,
        local_max_streams_uni: u64,
    ) -> ConcurrencyControl {
        let mut peer_bidi_avail_ids = ranges::RangeSet::default();
        peer_bidi_avail_ids.insert(0..local_max_streams_bidi);
        let mut peer_uni_avail_ids = ranges::RangeSet::default();
        peer_uni_avail_ids.insert(0..local_max_streams_uni);

        ConcurrencyControl {
            local_max_streams_bidi,
            local_max_streams_bidi_next: local_max_streams_bidi,
            local_max_streams_uni,
            local_max_streams_uni_next: local_max_streams_uni,
            peer_bidi_avail_ids,
            peer_uni_avail_ids,
            ..ConcurrencyControl::default()
        }
    }

    /// Update peer's max_streams limit after receiving a MAX_STREAMS(0x12..0x13) frame
    /// or processing peer's transport parameter.
    pub(super) fn update_peer_max_streams(&mut self, bidi: bool, max_streams: u64) {
        match bidi {
            true => {
                if self.peer_max_streams_bidi < max_streams {
                    // insert available ids for local initiated bidi-streams
                    let ids = self.peer_max_streams_bidi..max_streams;
                    self.insert_avail_id(ids, true, true);
                    self.peer_max_streams_bidi = max_streams;
                }

                // Cancel the concurrency control blocked state if the max_streams_bidi limit
                // is increased, avoid sending redundant STREAMS_BLOCKED(0x16) frames.
                if Some(self.peer_max_streams_bidi) > self.streams_blocked_at_bidi {
                    self.streams_blocked_at_bidi = None;
                }
            }

            false => {
                if self.peer_max_streams_uni < max_streams {
                    // insert available ids for local initiated uni-streams
                    let ids = self.peer_max_streams_uni..max_streams;
                    self.insert_avail_id(ids, true, false);
                    self.peer_max_streams_uni = max_streams;
                }

                // Cancel the concurrency control blocked state if the max_streams_uni limit
                // is increased, avoid sending redundant STREAMS_BLOCKED(type: 0x17) frames.
                if Some(self.peer_max_streams_uni) > self.streams_blocked_at_uni {
                    self.streams_blocked_at_uni = None;
                }
            }
        }
    }

    /// After sending a MAX_STREAMS(type: 0x12..0x13) frame, update local max_streams limit.
    pub(super) fn update_local_max_streams(&mut self, bidi: bool) {
        if bidi {
            // insert available ids for peer initiated bidi-streams
            let ids = self.local_max_streams_bidi..self.local_max_streams_bidi_next;
            self.insert_avail_id(ids, false, true);
            self.local_max_streams_bidi = self.local_max_streams_bidi_next;
        } else {
            // insert available ids for peer initiated uni-streams
            let ids = self.local_max_streams_uni..self.local_max_streams_uni_next;
            self.insert_avail_id(ids, false, false);
            self.local_max_streams_uni = self.local_max_streams_uni_next;
        }
    }

    /// Get the maximum number of streams that can be opened by the local endpoint.
    pub(super) fn peer_max_streams(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.peer_max_streams_bidi,
            false => self.peer_max_streams_uni,
        }
    }

    /// Get the remaining streams that local endpoint can open.
    pub(super) fn peer_streams_left(&self, bidi: bool) -> u64 {
        match bidi {
            true => self.peer_max_streams_bidi - self.local_opened_streams_bidi,
            false => self.peer_max_streams_uni - self.local_opened_streams_uni,
        }
    }

    /// Return true if the local max_streams limit should be updated
    /// by sending a MAX_STREAMS(type: 0x12..0x13) frame to the peer.
    //  The left stream count < 1/2 * max concurrent stream limits.
    pub(super) fn should_update_local_max_streams(&self, bidi: bool) -> bool {
        match bidi {
            true => {
                self.local_max_streams_bidi_next != self.local_max_streams_bidi
                    && self.local_max_streams_bidi_next - self.local_max_streams_bidi
                        > self.local_max_streams_bidi - self.peer_opened_streams_bidi
            }

            false => {
                self.local_max_streams_uni_next != self.local_max_streams_uni
                    && self.local_max_streams_uni_next - self.local_max_streams_uni
                        > self.local_max_streams_uni - self.peer_opened_streams_uni
            }
        }
    }

    /// Increase the next max_streams limit that will be sent to the peer
    /// in a MAX_STREAMS(type: 0x12..0x13) frame.
    pub(super) fn increase_max_streams_credits(&mut self, bidi: bool, delta: u64) {
        match bidi {
            true => {
                self.local_max_streams_bidi_next =
                    self.local_max_streams_bidi_next.saturating_add(delta)
            }
            false => {
                self.local_max_streams_uni_next =
                    self.local_max_streams_uni_next.saturating_add(delta)
            }
        }
    }

    /// Update connection concurrency control blocked state.
    pub(super) fn update_streams_blocked_at(&mut self, bidi: bool, blocket_at: Option<u64>) {
        match bidi {
            true => self.streams_blocked_at_bidi = blocket_at,
            false => self.streams_blocked_at_uni = blocket_at,
        }
    }

    /// Check if the stream ID complies with the stream limits of the current role,
    /// and try to update the stream count if the ID is valid.
    ///
    /// Note that the caller should ensure that the stream ID is valid with the
    /// initiator's role before calling this function.
    pub(super) fn check_concurrency_limits(&mut self, id: u64, is_server: bool) -> Result<()> {
        // The two least significant bits from a stream ID identify the stream type,
        // and stream sequence starts from 0.
        let stream_sequence = (id >> 2) + 1;

        // RFC 9000 4.6 Controlling Concurrency
        // Endpoints MUST NOT exceed the limit set by their peer. An endpoint that
        // receives a frame with a stream ID exceeding the limit it has sent MUST
        // treat this as a connection error of type STREAM_LIMIT_ERROR.
        match (is_local(id, is_server), is_bidi(id)) {
            (true, true) => {
                let n = std::cmp::max(self.local_opened_streams_bidi, stream_sequence);

                if n > self.peer_max_streams_bidi {
                    // Can't open more bidirectional streams than the peer allows, send
                    // a STREAMS_BLOCKED(type: 0x16) frame to notify the peer update the
                    // max_streams_bidi limit.
                    self.update_streams_blocked_at(true, Some(self.peer_max_streams_bidi));
                    return Err(Error::StreamLimitError);
                }

                self.local_opened_streams_bidi = cmp::max(self.local_opened_streams_bidi, n);
            }

            (true, false) => {
                let n = std::cmp::max(self.local_opened_streams_uni, stream_sequence);

                if n > self.peer_max_streams_uni {
                    // Can't open more unidirectional streams than the peer allows, send
                    // a STREAMS_BLOCKED(type: 0x17) frame to notify the peer update the
                    // max_streams_uni limit.
                    self.update_streams_blocked_at(false, Some(self.peer_max_streams_uni));
                    return Err(Error::StreamLimitError);
                }

                self.local_opened_streams_uni = cmp::max(self.local_opened_streams_uni, n);
            }

            (false, true) => {
                let n = std::cmp::max(self.peer_opened_streams_bidi, stream_sequence);

                if n > self.local_max_streams_bidi {
                    return Err(Error::StreamLimitError);
                }

                self.peer_opened_streams_bidi = cmp::max(self.peer_opened_streams_bidi, n);
            }

            (false, false) => {
                let n = std::cmp::max(self.peer_opened_streams_uni, stream_sequence);

                if n > self.local_max_streams_uni {
                    return Err(Error::StreamLimitError);
                }

                self.peer_opened_streams_uni = cmp::max(self.peer_opened_streams_uni, n);
            }
        };

        Ok(())
    }

    /// Check whether the given stream ID exceeds stream limits.
    pub(super) fn is_limited(&self, stream_id: u64, is_server: bool) -> bool {
        let seq = (stream_id >> 2) + 1;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => seq > self.peer_max_streams_bidi,
            (true, false) => seq > self.peer_max_streams_uni,
            (false, true) => seq > self.local_max_streams_bidi,
            (false, false) => seq > self.local_max_streams_uni,
        }
    }

    /// Check whether the given stream id is available for stream creation.
    pub(super) fn is_available(&self, stream_id: u64, is_server: bool) -> bool {
        let id = stream_id >> 2;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => self.local_bidi_avail_ids.contains(id),
            (true, false) => self.local_uni_avail_ids.contains(id),
            (false, true) => self.peer_bidi_avail_ids.contains(id),
            (false, false) => self.peer_uni_avail_ids.contains(id),
        }
    }

    /// Inset the given stream ids into available set.
    pub(super) fn insert_avail_id(&mut self, ids: Range<u64>, is_local: bool, is_bidi: bool) {
        match (is_local, is_bidi) {
            (true, true) => self.local_bidi_avail_ids.insert(ids),
            (true, false) => self.local_uni_avail_ids.insert(ids),
            (false, true) => self.peer_bidi_avail_ids.insert(ids),
            (false, false) => self.peer_uni_avail_ids.insert(ids),
        }
    }

    /// Remove the given stream id from available set.
    pub(super) fn remove_avail_id(&mut self, stream_id: u64, is_server: bool) {
        let id = stream_id >> 2;
        match (is_local(stream_id, is_server), is_bidi(stream_id)) {
            (true, true) => self.local_bidi_avail_ids.remove_elem(id),
            (true, false) => self.local_uni_avail_ids.remove_elem(id),
            (false, true) => self.peer_bidi_avail_ids.remove_elem(id),
            (false, false) => self.peer_uni_avail_ids.remove_elem(id),
        }
    }
}

/// Connection-level send capacity for all streams
#[derive(Clone, Debug, Default)]
pub(super) struct SendCapacity {
    /// The maximum amount of data that can be sent on the entire connection,
    /// in units of bytes.
    ///
    /// All data sent in STREAM frames counts toward this limit. The sum of the
    /// final sizes on all streams MUST NOT exceed this limit.
    ///
    /// Initially, this is set to the value of the initial_max_data transport
    /// parameter from peer. The value is also updated by MAX_DATA frames.
    pub(super) max_data: u64,

    /// The total amount of data sent on the entire connection, in units of bytes.
    ///
    /// When sending a STREAM frame, or receiving a STOP_SENDING frame, or shutting
    /// down a stream send-side, update this value.
    pub(super) tx_data: u64,

    /// Number of stream data that can be sent without exceeding the connection-level
    /// flow control limit, in units of bytes.
    pub(super) capacity: usize,

    /// Connection send-side blocked at(if any), and need to send a
    /// DATA_BLOCKED frame to the peer.
    pub(super) blocked_at: Option<u64>,
}

impl SendCapacity {
    /// Update the connection-level send-side max_data limit after
    /// processing peer's transport parameter initial_max_data(0x04)
    /// or receiving MAX_DATA frame.
    pub(super) fn update_max_data(&mut self, max_data: u64) {
        // ignore if the value is smaller than the current value.
        self.max_data = cmp::max(self.max_data, max_data);
    }

    /// Update connection-level send capacity.
    pub(super) fn update_capacity(&mut self) {
        self.capacity = (self.max_data - self.tx_data) as usize;
    }

    /// Update connection send-side flow control blocked state.
    pub(super) fn update_blocked_at(&mut self, blocked_at: Option<u64>) {
        self.blocked_at = blocked_at;
    }
}

/// Stream priority queue
///
/// Streams are categorized based on their urgency, where each urgency level
/// has two queues, including non-incremental and incremental streams.
///
/// Streams with lower urgency level are scheduled first, and within the
/// same urgency level non-incremental streams are scheduled before incremental
/// streams.
///
/// Non-incremental streams are scheduled in the order of their stream IDs.
/// Incremental streams are scheduled in a round-robin fashion.
#[derive(Debug, Default)]
pub(super) struct StreamPriorityQueue {
    /// Non-incremental streams.
    pub(super) non_incremental: BinaryHeap<std::cmp::Reverse<u64>>,
    /// Incremental streams.
    pub(super) incremental: VecDeque<u64>,
}
