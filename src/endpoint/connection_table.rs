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

//! Connection storage for the QUIC endpoint.

use rustc_hash::FxHashMap;

use crate::connection::Connection;

/// ConnectionTable is used for storing QUIC connections.
/// It provide pointer stability (the address of connections stored in the map
/// does not change), which makes the FFI API more easier to use.
pub(crate) struct ConnectionTable {
    pub(crate) conns: FxHashMap<u64, Box<Connection>>,
    next_index: u64,
}

impl ConnectionTable {
    pub(crate) fn new() -> Self {
        Self {
            conns: FxHashMap::default(),
            next_index: 0,
        }
    }

    /// Insert a QUIC connection
    pub(crate) fn insert(&mut self, conn: Connection) -> u64 {
        let index = self.next_index;
        self.next_index += 1;

        self.conns.insert(index, Box::new(conn));
        index
    }

    /// Get a QUIC connection by index
    pub(crate) fn get_mut(&mut self, index: u64) -> Option<&mut Box<Connection>> {
        self.conns.get_mut(&index)
    }

    /// Remove a QUIC connection by index
    pub(crate) fn remove(&mut self, index: u64) {
        self.conns.remove(&index);
    }

    /// Clear the connection table
    pub(crate) fn clear(&mut self) {
        self.conns.clear();
    }

    /// Return the number of connections
    pub(crate) fn len(&self) -> usize {
        self.conns.len()
    }

    /// Return true if there are no connections stored in the table.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
