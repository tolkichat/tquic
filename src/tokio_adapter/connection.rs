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
use std::time::Instant;

use bytes::Bytes;
use tokio::sync::mpsc;

use super::endpoint::{
    copy_connection_stats, extract_driver_waker, ConnectionInner, RECV_BUF_SIZE,
};
use super::error::AsyncError;
use super::stream::{RecvStream, SendStream};
use crate::connection::ConnectionStats;
use crate::{PacketInfo, Shutdown};

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
    /// Actively drives UDP I/O inline to avoid extra scheduling
    /// hops through the background `EndpointDriver`, reducing
    /// handshake latency by several milliseconds.
    ///
    /// Returns `Ok(())` when the handshake succeeds, or
    /// `Err(AsyncError::ConnectionClosed)` if the connection closes
    /// before the handshake finishes (e.g. TLS failure).
    pub async fn established(&self) -> Result<(), AsyncError> {
        let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
        let local_addr = self.inner.endpoint.shared.local_addr;

        loop {
            // Create notified futures BEFORE checking state to avoid race.
            let est_notified = self.inner.established_notify.notified();
            let close_notified = self.inner.close_notify.notified();

            if self.check_established()? {
                return Ok(());
            }

            // Try inline I/O: non-blocking recv + process.
            if self.try_drive_io(&mut recv_buf, local_addr) {
                continue;
            }

            // No packets available -- wait for socket or notify.
            tokio::select! {
                _ = est_notified => {},
                _ = close_notified => {},
                _ = self.inner.endpoint.shared.socket.readable() => {},
            }
        }
    }

    /// Check whether the handshake has completed or the connection
    /// has been closed.
    ///
    /// Returns `Ok(true)` if established, `Err` if closed.
    fn check_established(&self) -> Result<bool, AsyncError> {
        let cs = self.inner.conn_state.lock().expect("conn_state lock");
        if cs.is_established {
            return Ok(true);
        }
        if cs.close_info.is_some() {
            return Err(AsyncError::ConnectionClosed);
        }
        Ok(false)
    }

    /// Non-blocking receive-and-process loop.
    ///
    /// Reads packets from the shared socket and feeds them into the
    /// endpoint state machine. Returns `true` if at least one packet
    /// was processed (caller should re-check state immediately).
    fn try_drive_io(&self, recv_buf: &mut [u8], local_addr: SocketAddr) -> bool {
        let mut processed = false;
        loop {
            match self.inner.endpoint.shared.socket.try_recv_from(recv_buf) {
                Ok((n, src)) => {
                    let info = PacketInfo {
                        src,
                        dst: local_addr,
                        time: Instant::now(),
                    };
                    self.feed_packet(&recv_buf[..n], &info);
                    processed = true;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(ref e)
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    continue;
                }
                Err(_) => break,
            }
        }
        processed
    }

    /// Feed a single received packet into the endpoint and wake the
    /// driver so it can send any response packets.
    fn feed_packet(&self, data: &[u8], info: &PacketInfo) {
        let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
        // recv() takes &mut [u8] for in-place decryption.
        let mut buf = data.to_vec();
        let _ = state.endpoint().recv(&mut buf, info);
        let _ = state.endpoint().process_connections();
        let waker = extract_driver_waker(&state);
        drop(state);
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Open a new bidirectional QUIC stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), AsyncError> {
        let (stream_id, waker) = {
            let mut state = self.inner.endpoint.state.lock().expect("endpoint lock");
            let conn = state
                .endpoint()
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
                .endpoint()
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
                .endpoint()
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
                if let Some(conn) = state.endpoint().conn_get_mut(self.inner.index) {
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
            if let Some(conn) = state.endpoint().conn_get_mut(self.inner.index) {
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
            .endpoint()
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
