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

//! Async QUIC connection handle.
//!
//! [`TquicConnection`] is a `Send`-safe handle to a QUIC connection
//! managed by the driver on a `LocalSet`. All operations are forwarded
//! to the driver via channels.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, watch, Notify};

use super::error::AsyncError;
use super::stream::{RecvStream, SendStream, StreamCmd};
use crate::connection::ConnectionStats;

/// Information about why a connection was closed.
#[derive(Clone, Debug)]
pub struct ConnectionCloseInfo {
    /// Whether the close was initiated by the application layer.
    pub is_app: bool,

    /// The error code carried in the CONNECTION_CLOSE frame.
    pub error_code: u64,

    /// Human-readable reason phrase.
    pub reason: Vec<u8>,
}

/// Commands sent from the connection handle to the driver.
pub(crate) enum ConnCmd {
    /// Open a new bidirectional stream.
    OpenBi {
        result_tx: oneshot::Sender<Result<(SendStream, RecvStream), AsyncError>>,
    },
    /// Open a new unidirectional stream.
    OpenUni {
        result_tx: oneshot::Sender<Result<SendStream, AsyncError>>,
    },
    /// Send an unreliable datagram.
    SendDatagram {
        data: Bytes,
        result_tx: oneshot::Sender<Result<(), AsyncError>>,
    },
    /// Receive an unreliable datagram.
    RecvDatagram {
        result_tx: oneshot::Sender<Result<Bytes, AsyncError>>,
    },
    /// Close the connection.
    Close { error_code: u64, reason: Vec<u8> },
    /// Retrieve connection statistics.
    GetStats {
        result_tx: oneshot::Sender<ConnectionStats>,
    },
}

/// A `Send`-safe handle to a QUIC connection.
///
/// Operations are forwarded to the driver event loop via channels.
/// The connection can be used from any tokio task.
pub struct TquicConnection {
    /// The connection index in the endpoint's connection table.
    pub(crate) index: u64,

    /// Channel for sending connection-level commands to the driver.
    pub(crate) cmd_tx: mpsc::Sender<ConnCmd>,

    /// Channel for sending stream-level commands to the driver.
    pub(crate) stream_cmd_tx: mpsc::Sender<StreamCmd>,

    /// Notified when the handshake completes.
    pub(crate) established: Arc<Notify>,

    /// Watch channel receiving close information when connection ends.
    pub(crate) close_rx: watch::Receiver<Option<ConnectionCloseInfo>>,

    /// Receiver for incoming bidirectional streams.
    pub(crate) incoming_bi_rx: mpsc::Receiver<(SendStream, RecvStream)>,

    /// Receiver for incoming unidirectional streams.
    pub(crate) incoming_uni_rx: mpsc::Receiver<RecvStream>,

    /// The remote peer's address.
    pub(crate) remote_addr: SocketAddr,
}

impl TquicConnection {
    /// Wait for the QUIC handshake to complete.
    pub async fn established(&self) {
        self.established.notified().await;
    }

    /// Open a new bidirectional QUIC stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::OpenBi { result_tx })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)?
    }

    /// Open a new unidirectional QUIC stream.
    pub async fn open_uni(&self) -> Result<SendStream, AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::OpenUni { result_tx })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)?
    }

    /// Accept an incoming bidirectional stream from the peer.
    ///
    /// Returns `None` if the connection has been closed.
    pub async fn accept_bi(&mut self) -> Option<(SendStream, RecvStream)> {
        self.incoming_bi_rx.recv().await
    }

    /// Accept an incoming unidirectional stream from the peer.
    ///
    /// Returns `None` if the connection has been closed.
    pub async fn accept_uni(&mut self) -> Option<RecvStream> {
        self.incoming_uni_rx.recv().await
    }

    /// Send an unreliable datagram over the connection.
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::SendDatagram { data, result_tx })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)?
    }

    /// Receive an unreliable datagram from the connection.
    pub async fn read_datagram(&self) -> Result<Bytes, AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::RecvDatagram { result_tx })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)?
    }

    /// Close the connection with the given error code and reason.
    pub fn close(&self, error_code: u64, reason: &[u8]) {
        let _ = self.cmd_tx.try_send(ConnCmd::Close {
            error_code,
            reason: reason.to_vec(),
        });
    }

    /// Retrieve connection statistics.
    pub async fn stats(&self) -> Result<ConnectionStats, AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(ConnCmd::GetStats { result_tx })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)
    }

    /// Return the remote peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Check whether the connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.close_rx.borrow().is_some()
    }

    /// Wait until the connection is closed and return close info.
    pub async fn closed(&mut self) -> ConnectionCloseInfo {
        loop {
            if let Some(info) = self.close_rx.borrow().clone() {
                return info;
            }
            if self.close_rx.changed().await.is_err() {
                return ConnectionCloseInfo {
                    is_app: false,
                    error_code: 0,
                    reason: b"channel dropped".to_vec(),
                };
            }
        }
    }
}
