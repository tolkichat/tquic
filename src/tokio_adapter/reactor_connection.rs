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

//! User-facing TquicConnection for the reactor pattern.
//!
//! All operations communicate with the reactor task via channels.
//! No mutexes are needed.

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use super::cmd::{ControlCmd, DataCmd, IncomingBiStream, IncomingUniStream, SharedConnState};
use super::direct_stream::{RecvStream, SendStream};
use super::error::AsyncError;
use super::reactor::CloseInfo;
use super::shared::SharedState;
use crate::connection::ConnectionStats;

/// Close information for a connection.
#[derive(Clone, Debug)]
pub struct ConnectionCloseInfo {
    /// Whether the close was initiated by the application layer.
    pub is_app: bool,

    /// The error code carried in the CONNECTION_CLOSE frame.
    pub error_code: u64,

    /// Human-readable reason phrase.
    pub reason: Vec<u8>,
}

/// A `Send + Sync` async QUIC connection handle (reactor version).
///
/// Holds channel senders for communicating with the reactor
/// and shared endpoint state for direct-call stream I/O.
pub struct TquicConnection {
    /// The tquic connection index within the endpoint.
    conn_index: u64,

    /// The remote peer's address.
    remote_addr: SocketAddr,

    /// Sender for control-plane commands.
    control_tx: mpsc::Sender<ControlCmd>,

    /// Sender for data-plane commands.
    data_tx: mpsc::Sender<DataCmd>,

    /// Shared lifecycle state with the reactor.
    shared: Arc<SharedConnState>,

    /// Shared endpoint state for direct-call stream I/O.
    shared_inner: SharedState,

    /// Wake the driver to call `process_connections` / send packets.
    driver_notify: Arc<Notify>,

    /// Receiver for incoming bidirectional streams from the peer.
    incoming_bi_rx: mpsc::Receiver<IncomingBiStream>,

    /// Receiver for incoming unidirectional streams from the peer.
    incoming_uni_rx: mpsc::Receiver<IncomingUniStream>,

    /// UDP socket for unlock-before-send in stream handles.
    socket: Arc<UdpSocket>,
}

impl TquicConnection {
    /// Create a new connection handle.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        conn_index: u64,
        remote_addr: SocketAddr,
        control_tx: mpsc::Sender<ControlCmd>,
        data_tx: mpsc::Sender<DataCmd>,
        shared: Arc<SharedConnState>,
        shared_inner: SharedState,
        driver_notify: Arc<Notify>,
        incoming_bi_rx: mpsc::Receiver<IncomingBiStream>,
        incoming_uni_rx: mpsc::Receiver<IncomingUniStream>,
        socket: Arc<UdpSocket>,
    ) -> Self {
        Self {
            conn_index,
            remote_addr,
            control_tx,
            data_tx,
            shared,
            shared_inner,
            driver_notify,
            incoming_bi_rx,
            incoming_uni_rx,
            socket,
        }
    }

    /// Wait for the QUIC handshake to complete.
    ///
    /// In the reactor pattern, `connect()` returns the connection handle
    /// on `on_conn_created` (before handshake completes). This method
    /// waits for the reactor to signal `on_conn_established`.
    pub async fn established(&self) -> Result<(), AsyncError> {
        loop {
            if self.shared.is_established.load(Ordering::Acquire) {
                return Ok(());
            }
            if self.is_closed() {
                return Err(AsyncError::ConnectionClosed);
            }
            let notified = self.shared.established.notified();
            // Re-check after registering to avoid race.
            if self.shared.is_established.load(Ordering::Acquire) {
                return Ok(());
            }
            tokio::select! {
                () = notified => {}
                () = self.shared.closed.notified() => {
                    return Err(AsyncError::ConnectionClosed);
                }
            }
        }
    }

    /// Open a new bidirectional QUIC stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(ControlCmd::OpenBi {
                conn_index: self.conn_index,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;

        let result = rx.await.map_err(|_| AsyncError::ReactorGone)??;
        let send = SendStream::new(
            result.send_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        );
        let recv = RecvStream::new(
            result.recv_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        );
        Ok((send, recv))
    }

    /// Open a new unidirectional QUIC stream.
    pub async fn open_uni(&self) -> Result<SendStream, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(ControlCmd::OpenUni {
                conn_index: self.conn_index,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;

        let result = rx.await.map_err(|_| AsyncError::ReactorGone)??;
        Ok(SendStream::new(
            result.stream_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        ))
    }

    /// Accept an incoming bidirectional stream from the peer.
    ///
    /// Returns `None` if the connection has been closed.
    pub async fn accept_bi(&mut self) -> Option<(SendStream, RecvStream)> {
        let incoming = self.incoming_bi_rx.recv().await?;
        let send = SendStream::new(
            incoming.send_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        );
        let recv = RecvStream::new(
            incoming.recv_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        );
        Some((send, recv))
    }

    /// Accept an incoming unidirectional stream from the peer.
    ///
    /// Returns `None` if the connection has been closed.
    pub async fn accept_uni(&mut self) -> Option<RecvStream> {
        let incoming = self.incoming_uni_rx.recv().await?;
        Some(RecvStream::new(
            incoming.stream_id,
            self.conn_index,
            self.shared_inner.clone(),
            Arc::clone(&self.driver_notify),
            self.data_tx.clone(),
            Arc::clone(&self.socket),
        ))
    }

    /// Send an unreliable datagram.
    pub async fn send_datagram(&self, data: Bytes) -> Result<(), AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.data_tx
            .send(DataCmd::DgramSend {
                conn_index: self.conn_index,
                data,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        rx.await.map_err(|_| AsyncError::ReactorGone)?
    }

    /// Receive an unreliable datagram.
    pub async fn read_datagram(&self) -> Result<Bytes, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.data_tx
            .send(DataCmd::DgramRecv {
                conn_index: self.conn_index,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        rx.await.map_err(|_| AsyncError::ReactorGone)?
    }

    /// Close the connection with the given error code and reason.
    pub fn close(&self, error_code: u64, reason: &[u8]) {
        let _ = self.control_tx.try_send(ControlCmd::Close {
            conn_index: self.conn_index,
            error_code,
            reason: reason.to_vec(),
        });
    }

    /// Retrieve connection statistics.
    pub async fn stats(&self) -> Result<ConnectionStats, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(ControlCmd::Stats {
                conn_index: self.conn_index,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        rx.await.map_err(|_| AsyncError::ReactorGone)?
    }

    /// Return the remote peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Check if the connection is closed.
    pub fn is_closed(&self) -> bool {
        self.shared
            .close_info
            .lock()
            .expect("close_info lock")
            .is_some()
    }

    /// Wait until the connection is closed and return the close info.
    pub async fn closed(&mut self) -> ConnectionCloseInfo {
        loop {
            if let Some(info) = self.close_info_snapshot() {
                return info;
            }
            self.shared.closed.notified().await;
        }
    }

    /// Read the close info if available.
    fn close_info_snapshot(&self) -> Option<ConnectionCloseInfo> {
        self.shared
            .close_info
            .lock()
            .expect("close_info lock")
            .as_ref()
            .map(|ci| ConnectionCloseInfo {
                is_app: ci.is_app,
                error_code: ci.error_code,
                reason: ci.reason.clone(),
            })
    }
}
