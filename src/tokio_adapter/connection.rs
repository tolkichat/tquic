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
//! [`TquicConnection`] directly locks the endpoint state to
//! perform operations on the underlying tquic `Connection`,
//! eliminating the channel-based indirection of the old design.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::endpoint::{copy_connection_stats, extract_driver_waker, ConnectionInner};
use super::error::AsyncError;
use super::stream::{RecvStream, SendStream};
use crate::connection::ConnectionStats;
use crate::Shutdown;

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

/// A `Send + Sync` async QUIC connection handle.
///
/// Operations directly lock the endpoint state and call tquic
/// methods, waking the driver afterwards to flush packets.
pub struct TquicConnection {
    /// Shared connection state.
    pub(crate) inner: Arc<ConnectionInner>,

    /// Receiver for incoming bidirectional streams.
    pub(crate) incoming_bi_rx: mpsc::Receiver<(SendStream, RecvStream)>,

    /// Receiver for incoming unidirectional streams.
    pub(crate) incoming_uni_rx: mpsc::Receiver<RecvStream>,
}

impl TquicConnection {
    /// Wait for the QUIC handshake to complete.
    ///
    /// Returns `Ok(())` when the handshake succeeds, or
    /// `Err(AsyncError::ConnectionClosed)` if the connection closes
    /// before the handshake finishes (e.g. TLS failure).
    pub async fn established(&self) -> Result<(), AsyncError> {
        loop {
            // Create notified futures BEFORE checking state to avoid race.
            let est_notified = self.inner.established_notify.notified();
            let close_notified = self.inner.close_notify.notified();
            {
                let state = self.inner.conn_state.lock().expect("conn_state lock");
                if state.is_established {
                    return Ok(());
                }
                if state.close_info.is_some() {
                    return Err(AsyncError::ConnectionClosed);
                }
            }
            tokio::select! {
                _ = est_notified => {},
                _ = close_notified => {},
            }
        }
    }

    /// Open a new bidirectional QUIC stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), AsyncError> {
        let (stream_id, waker) = {
            let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
            let conn = state
                .endpoint
                .conn_get_mut(self.inner.index)
                .ok_or(AsyncError::ConnectionClosed)?;
            let sid = conn.stream_bidi_new(0, false).map_err(AsyncError::Tquic)?;
            let w = extract_driver_waker(&state);
            (sid, w)
        };

        if let Some(w) = waker {
            w.wake();
        }

        let send = SendStream::new(stream_id, self.inner.index, Arc::clone(&self.inner));
        let recv = RecvStream::new(stream_id, self.inner.index, Arc::clone(&self.inner));
        Ok((send, recv))
    }

    /// Open a new unidirectional QUIC stream.
    pub async fn open_uni(&self) -> Result<SendStream, AsyncError> {
        let (stream_id, waker) = {
            let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
            let conn = state
                .endpoint
                .conn_get_mut(self.inner.index)
                .ok_or(AsyncError::ConnectionClosed)?;
            let sid = conn.stream_uni_new(0, false).map_err(AsyncError::Tquic)?;
            let w = extract_driver_waker(&state);
            (sid, w)
        };

        if let Some(w) = waker {
            w.wake();
        }

        Ok(SendStream::new(
            stream_id,
            self.inner.index,
            Arc::clone(&self.inner),
        ))
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
        let waker = {
            let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
            let conn = state
                .endpoint
                .conn_get_mut(self.inner.index)
                .ok_or(AsyncError::ConnectionClosed)?;
            conn.dgram_send(data).map_err(AsyncError::Tquic)?;
            extract_driver_waker(&state)
        };

        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }

    /// Receive an unreliable datagram from the connection.
    ///
    /// Blocks until a datagram is available via the `dgram_notify` signal.
    pub async fn read_datagram(&self) -> Result<Bytes, AsyncError> {
        loop {
            // Create `Notified` BEFORE checking state to avoid race.
            let notified = self.inner.dgram_notify.notified();
            {
                let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
                if let Some(conn) = state.endpoint.conn_get_mut(self.inner.index) {
                    match conn.dgram_recv() {
                        Ok(data) => return Ok(data),
                        Err(crate::Error::Done) => {} // No data yet.
                        Err(e) => return Err(AsyncError::Tquic(e)),
                    }
                } else {
                    return Err(AsyncError::ConnectionClosed);
                }
            }

            notified.await;
        }
    }

    /// Close the connection with the given error code and reason.
    pub fn close(&self, error_code: u64, reason: &[u8]) {
        let waker = {
            let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
            if let Some(conn) = state.endpoint.conn_get_mut(self.inner.index) {
                let _ = conn.close(true, error_code, reason);
            }
            extract_driver_waker(&state)
        };

        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Retrieve connection statistics.
    pub async fn stats(&self) -> Result<ConnectionStats, AsyncError> {
        let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
        let conn = state
            .endpoint
            .conn_get_mut(self.inner.index)
            .ok_or(AsyncError::ConnectionClosed)?;
        Ok(copy_connection_stats(conn))
    }

    /// Return the remote peer's address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.inner.remote_addr
    }

    /// Check whether the connection has been closed.
    pub fn is_closed(&self) -> bool {
        self.inner
            .conn_state
            .lock()
            .expect("conn_state lock")
            .close_info
            .is_some()
    }

    /// Wait until the connection is closed and return close info.
    pub async fn closed(&mut self) -> ConnectionCloseInfo {
        loop {
            // Create `Notified` BEFORE checking state to avoid race.
            let notified = self.inner.close_notify.notified();
            {
                let state = self.inner.conn_state.lock().expect("conn_state lock");
                if let Some(info) = state.close_info.clone() {
                    return info;
                }
            }
            notified.await;
        }
    }
}
