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

//! Command types for the single-owner reactor.
//!
//! Two separate channels prevent high-frequency stream data
//! from blocking low-frequency control operations like connect.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, Notify};

use super::error::AsyncError;
use super::reactor::CloseInfo;
use crate::connection::ConnectionStats;
use crate::Shutdown;

/// Result of a successful stream read.
pub struct ReadResult {
    /// The data read from the stream.
    pub data: Vec<u8>,

    /// Whether the FIN flag was set (stream fully received).
    pub fin: bool,
}

/// Shared connection state between the reactor and user handles.
///
/// Allows the user-facing `TquicConnection` to observe connection
/// lifecycle events without sending commands through the channel.
pub(crate) struct SharedConnState {
    /// Whether the handshake has completed.
    pub(crate) is_established: AtomicBool,

    /// Notified when the handshake completes.
    pub(crate) established: Notify,

    /// Notified when the connection closes.
    pub(crate) closed: Notify,

    /// Close info, set by the reactor before notifying.
    pub(crate) close_info: std::sync::Mutex<Option<CloseInfo>>,
}

/// Handle returned after a successful connect/accept.
///
/// Contains the connection index, remote address, and channels
/// for incoming peer-initiated streams.
pub struct ConnHandle {
    /// The tquic connection index within the endpoint.
    pub conn_index: u64,

    /// The remote peer's address.
    pub remote_addr: SocketAddr,

    /// Shared connection lifecycle state.
    pub(crate) shared: Arc<SharedConnState>,

    /// Receiver for incoming bidirectional streams.
    pub(crate) incoming_bi_rx: mpsc::Receiver<(u64, u64)>,

    /// Receiver for incoming unidirectional streams.
    pub(crate) incoming_uni_rx: mpsc::Receiver<u64>,
}

/// Control-plane commands (low frequency, always need a response).
pub enum ControlCmd {
    /// Initiate a connection to a remote peer.
    Connect {
        remote: SocketAddr,
        server_name: String,
        session: Option<Vec<u8>>,
        token: Option<Vec<u8>>,
        tx: oneshot::Sender<Result<ConnHandle, AsyncError>>,
    },

    /// Open a new bidirectional stream.
    OpenBi {
        conn_index: u64,
        tx: oneshot::Sender<Result<(u64, u64), AsyncError>>,
    },

    /// Open a new unidirectional stream.
    OpenUni {
        conn_index: u64,
        tx: oneshot::Sender<Result<u64, AsyncError>>,
    },

    /// Close a connection (fire-and-forget).
    Close {
        conn_index: u64,
        error_code: u64,
        reason: Vec<u8>,
    },

    /// Retrieve connection statistics.
    Stats {
        conn_index: u64,
        tx: oneshot::Sender<Result<ConnectionStats, AsyncError>>,
    },

    /// Shut down the reactor.
    Shutdown,
}

/// Data-plane commands (high frequency).
pub enum DataCmd {
    /// Write data to a stream.
    StreamWrite {
        conn_index: u64,
        stream_id: u64,
        data: Bytes,
        fin: bool,
        tx: oneshot::Sender<Result<usize, AsyncError>>,
    },

    /// Read data from a stream.
    StreamRead {
        conn_index: u64,
        stream_id: u64,
        buf_len: usize,
        tx: oneshot::Sender<Result<ReadResult, AsyncError>>,
    },

    /// Shut down one direction of a stream (fire-and-forget).
    StreamShutdown {
        conn_index: u64,
        stream_id: u64,
        direction: Shutdown,
        error_code: u64,
    },

    /// Send an unreliable datagram.
    DgramSend {
        conn_index: u64,
        data: Bytes,
        tx: oneshot::Sender<Result<(), AsyncError>>,
    },

    /// Receive an unreliable datagram.
    DgramRecv {
        conn_index: u64,
        tx: oneshot::Sender<Result<Bytes, AsyncError>>,
    },
}
