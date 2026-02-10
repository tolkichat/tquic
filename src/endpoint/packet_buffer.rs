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

//! Buffer for early incoming ZeroRTT packets on the server.

use crate::ConnectionId;
use crate::PacketInfo;

/// Maximum number of ZeroRTT packets buffered per connection.
const MAX_ZERORTT_PACKETS_PER_CONN: usize = 10;

/// PacketBuffer is used for buffering early incoming ZeroRTT packets on the server.
/// Buffered packets are indexed by odcid.
pub(crate) struct PacketBuffer {
    packets: lru::LruCache<ConnectionId, Vec<(Vec<u8>, PacketInfo)>>,
}

impl PacketBuffer {
    pub(crate) fn new(cache_size: usize) -> Self {
        let size =
            std::num::NonZeroUsize::new(cache_size).expect("zerortt_buffer_size must be non-zero");
        Self {
            packets: lru::LruCache::new(size),
        }
    }

    /// Buffer a ZeroRTT packet for the given connection.
    pub(crate) fn add(&mut self, dcid: ConnectionId, buffer: Vec<u8>, info: PacketInfo) {
        if let Some(v) = self.packets.get_mut(&dcid) {
            if v.len() < MAX_ZERORTT_PACKETS_PER_CONN {
                v.push((buffer, info));
            }
            return;
        }

        let mut v = Vec::with_capacity(MAX_ZERORTT_PACKETS_PER_CONN);
        v.push((buffer, info));
        self.packets.put(dcid, v);
    }

    /// Remove all packets for the specified connection.
    pub(crate) fn del(&mut self, dcid: &ConnectionId) -> Option<Vec<(Vec<u8>, PacketInfo)>> {
        self.packets.pop(dcid)
    }
}
