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

//! Packet routing for matching incoming packets to connections.

use std::collections::HashMap;

use rustc_hash::FxHashMap;

use crate::connection::Connection;
use crate::token::ResetToken;
use crate::ConnectionId;
use crate::FourTuple;
use crate::PacketInfo;

/// ConnectionRoutes is used for matching incoming packets to connections.
/// See RFC 9000 Section 5.2
pub(crate) struct ConnectionRoutes {
    /// Connections identified based on the locally created CID.
    pub(crate) cid_table: FxHashMap<ConnectionId, u64>,

    /// Connections(with zero-length CID) identified based on the address tuple.
    addr_table: HashMap<FourTuple, u64>,

    /// Connections identified based on the stateless reset token.
    token_table: FxHashMap<ResetToken, u64>,
}

impl ConnectionRoutes {
    pub(crate) fn new() -> Self {
        Self {
            cid_table: FxHashMap::default(),
            addr_table: HashMap::default(),
            token_table: FxHashMap::default(),
        }
    }

    /// Find the target connection for the incoming datagram.
    pub(crate) fn find(
        &self,
        dcid: &ConnectionId,
        buf: &mut [u8],
        info: &PacketInfo,
    ) -> (Option<&u64>, bool) {
        let mut reset = false;
        let mut idx = if !dcid.is_empty() {
            self.cid_table.get(dcid)
        } else {
            let addr = FourTuple {
                local: info.dst,
                remote: info.src,
            };
            self.addr_table.get(&addr)
        };

        if idx.is_none() && buf.len() > crate::RESET_TOKEN_LEN {
            let token = match ResetToken::from_bytes(buf) {
                Ok(t) => t,
                Err(_) => return (None, false),
            };
            idx = self.token_table.get(&token);
            if idx.is_some() {
                reset = true;
            }
        }

        (idx, reset)
    }

    /// Insert the local cid and the connection.
    pub(crate) fn insert_with_cid(&mut self, cid: ConnectionId, idx: u64) {
        self.cid_table.insert(cid, idx);
    }

    /// Remove the entry for the given cid.
    pub(crate) fn remove_with_cid(&mut self, cid: &ConnectionId) {
        self.cid_table.remove(cid);
    }

    /// Insert the address tuple and the connection.
    pub(crate) fn insert_with_addr(&mut self, addr: FourTuple, idx: u64) {
        self.addr_table.insert(addr, idx);
    }

    /// Remove the entry for the given address tuple.
    fn remove_with_addr(&mut self, addr: &FourTuple) {
        self.addr_table.remove(addr);
    }

    /// Insert the stateless reset token and the connection.
    pub(crate) fn insert_with_token(&mut self, token: ResetToken, idx: u64) {
        self.token_table.insert(token, idx);
    }

    /// Remove the entry for the given reset token.
    pub(crate) fn remove_with_token(&mut self, token: &ResetToken) {
        self.token_table.remove(token);
    }

    /// Remove all routes for the connection
    pub(crate) fn remove(&mut self, conn: &Connection) {
        self.remove_cid_or_addr_routes(conn);
        self.remove_odcid_route(conn);
        self.remove_reset_token_routes(conn);
    }

    /// Remove routes based on scid or address tuple.
    fn remove_cid_or_addr_routes(&mut self, conn: &Connection) {
        if !conn.zero_length_scid() {
            for c in conn.scid_iter() {
                self.remove_with_cid(&c.cid);
            }
        } else {
            for ref p in conn.paths_iter() {
                self.remove_with_addr(p);
            }
        }
    }

    /// Remove routes based on original dcid.
    fn remove_odcid_route(&mut self, conn: &Connection) {
        if conn.is_server() {
            if let Some(odcid) = conn.odcid() {
                self.remove_with_cid(&odcid);
            }
        }
    }

    /// Remove routes based on stateless reset token.
    fn remove_reset_token_routes(&mut self, conn: &Connection) {
        if !conn.zero_length_dcid() {
            for c in conn.dcid_iter() {
                if let Some(token) = c.reset_token {
                    let token = ResetToken(token.to_be_bytes());
                    self.remove_with_token(&token);
                }
            }
        }
    }

    /// Clear all the routes.
    pub(crate) fn clear(&mut self) {
        self.cid_table.clear();
        self.addr_table.clear();
        self.token_table.clear();
    }
}
