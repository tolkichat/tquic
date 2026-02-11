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

//! TransportHandler for the reactor pattern.
//!
//! Runs inside the reactor task. Callbacks from
//! `Endpoint::process_connections()` send events through channels
//! so the reactor can update its bookkeeping after the call returns.

use std::net::SocketAddr;

use log::*;
use tokio::sync::mpsc;

use crate::connection::Connection;
use crate::TransportHandler;

/// Events emitted by the handler during `process_connections()`.
///
/// Collected by the reactor after each process cycle.
pub(crate) enum HandlerEvent {
    /// A new connection was created.
    ConnCreated { index: u64, remote: SocketAddr },

    /// A connection handshake completed.
    ConnEstablished { index: u64 },

    /// A connection was closed.
    ConnClosed {
        index: u64,
        is_app: bool,
        error_code: u64,
        reason: Vec<u8>,
    },

    /// A peer-initiated stream was created.
    StreamCreated { index: u64, stream_id: u64 },

    /// A stream has data available for reading.
    StreamReadable { index: u64, stream_id: u64 },

    /// A stream has capacity for writing.
    StreamWritable { index: u64, stream_id: u64 },

    /// A stream was closed.
    StreamClosed { index: u64, stream_id: u64 },

    /// A datagram is available for reading.
    DgramReadable { index: u64 },

    /// A new session token was received (for 0-RTT).
    NewToken { index: u64, token: Vec<u8> },
}

/// TransportHandler that buffers events for the reactor.
pub(crate) struct ReactorHandler {
    /// Channel to send events to the reactor.
    event_tx: mpsc::UnboundedSender<HandlerEvent>,

    /// Whether this is a server endpoint.
    is_server: bool,
}

impl ReactorHandler {
    /// Create a new reactor handler.
    pub(crate) fn new(event_tx: mpsc::UnboundedSender<HandlerEvent>, is_server: bool) -> Self {
        Self {
            event_tx,
            is_server,
        }
    }

    /// Extract the remote address from a connection's path list.
    fn remote_addr_of(conn: &Connection) -> SocketAddr {
        conn.paths_iter()
            .next()
            .map_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)), |ft| ft.remote)
    }

    /// Send an event to the reactor, logging if the channel is closed.
    fn send(&self, event: HandlerEvent) {
        if self.event_tx.send(event).is_err() {
            warn!("reactor handler: event channel closed");
        }
    }
}

impl TransportHandler for ReactorHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let remote = Self::remote_addr_of(conn);
        self.send(HandlerEvent::ConnCreated { index, remote });
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::ConnEstablished { index });
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let (is_app, error_code, reason) = conn
            .peer_error()
            .or(conn.local_error())
            .map_or((false, 0, Vec::new()), |err| {
                (err.is_app, err.error_code, err.reason.clone())
            });
        self.send(HandlerEvent::ConnClosed {
            index,
            is_app,
            error_code,
            reason,
        });
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        // Only report peer-initiated streams.
        let is_local = (stream_id & 0x1 == 0) != self.is_server;
        if !is_local {
            self.send(HandlerEvent::StreamCreated { index, stream_id });
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::StreamReadable { index, stream_id });
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::StreamWritable { index, stream_id });
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::StreamClosed { index, stream_id });
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::NewToken { index, token });
    }

    fn on_dgram_readable(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        self.send(HandlerEvent::DgramReadable { index });
    }
}
