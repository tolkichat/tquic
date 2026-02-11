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

//! Async QUIC endpoint.
//!
//! [`TquicEndpoint`] wraps a tquic `Endpoint` behind `Arc<Mutex>`,
//! exposing `Send + Sync` async APIs. An [`EndpointDriver`] Future
//! (spawned via `tokio::spawn`) handles UDP I/O and drives the
//! tquic state machine.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::*;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Notify};

use super::connection::{ConnectionCloseInfo, TquicConnection};
use super::error::AsyncError;
use super::stream::{RecvStream, SendStream};
use crate::connection::Connection;
use crate::{Config, Endpoint, PacketInfo, PacketSendHandler, SharedRc, TransportHandler};

/// Maximum UDP receive buffer size (64 KiB).
pub(crate) const RECV_BUF_SIZE: usize = 65536;

/// Maximum iterations per poll to avoid starving other tasks.
const IO_LOOP_BOUND: usize = 10;

/// Fallback timer when the endpoint has no pending timers.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_millis(100);

/// Channel capacity for incoming connections.
const INCOMING_CONN_CAP: usize = 256;

/// Channel capacity for incoming streams per connection.
const INCOMING_STREAM_CAP: usize = 256;

// ---------------------------------------------------------------------------
// Core inner types
// ---------------------------------------------------------------------------

/// Shared state for a single connection's async operations.
pub(crate) struct ConnectionInner {
    /// Back-pointer to the parent endpoint.
    pub(crate) endpoint: Arc<EndpointInner>,

    /// Per-stream read/write wakers and close state.
    pub(crate) conn_state: Mutex<ConnAsyncState>,

    /// Notified when the QUIC handshake completes.
    pub(crate) established_notify: Notify,

    /// Notified when the connection is closed.
    pub(crate) close_notify: Notify,

    /// Notified when a DATAGRAM frame is received.
    pub(crate) dgram_notify: Notify,

    /// The tquic connection index within the endpoint.
    pub(crate) index: u64,

    /// The remote peer's address.
    pub(crate) remote_addr: SocketAddr,
}

/// Mutable per-connection async state, protected by its own mutex.
pub(crate) struct ConnAsyncState {
    /// Wakers for stream read operations, keyed by stream ID.
    pub(crate) read_wakers: HashMap<u64, Waker>,

    /// Wakers for stream write operations, keyed by stream ID.
    pub(crate) write_wakers: HashMap<u64, Waker>,

    /// Close information, set when the connection terminates.
    pub(crate) close_info: Option<ConnectionCloseInfo>,

    /// Sender for incoming bidirectional streams from the peer.
    pub(crate) incoming_bi_tx: Option<mpsc::Sender<(SendStream, RecvStream)>>,

    /// Sender for incoming unidirectional streams from the peer.
    pub(crate) incoming_uni_tx: Option<mpsc::Sender<RecvStream>>,

    /// Whether the connection handshake has completed.
    pub(crate) is_established: bool,
}

/// Holds the result of a client-side `connect()` before the user picks it up.
pub(crate) struct PendingConnResult {
    pub(crate) conn_inner: Arc<ConnectionInner>,
    pub(crate) incoming_bi_rx: mpsc::Receiver<(SendStream, RecvStream)>,
    pub(crate) incoming_uni_rx: mpsc::Receiver<RecvStream>,
}

/// Shared state between [`AdapterHandler`] and user-facing API.
///
/// The handler callbacks fire while `EndpointState` is locked.
/// This struct uses its own mutexes so both the handler and user
/// code can access it (with consistent lock ordering).
pub(crate) struct HandlerShared {
    /// Active connections keyed by tquic connection index.
    pub(crate) connections: Mutex<HashMap<u64, Arc<ConnectionInner>>>,

    /// Per-connect results keyed by connection index.
    ///
    /// Using a map instead of `Option` prevents concurrent `connect()`
    /// calls from overwriting each other's results.
    pub(crate) pending_connects: Mutex<HashMap<u64, PendingConnResult>>,
}

/// Mutable endpoint-level state, behind a `Mutex`.
pub(crate) struct EndpointState {
    /// The tquic endpoint (owns all connections).
    ///
    /// `None` only during the brief two-step init window; always
    /// `Some` by the time any user or driver code runs.
    pub(crate) endpoint: Option<Endpoint>,

    /// The waker for the [`EndpointDriver`] Future.
    pub(crate) driver_waker: Option<Waker>,

    /// Whether the endpoint has been shut down.
    pub(crate) closed: bool,
}

impl EndpointState {
    /// Mutable access to the initialized endpoint.
    ///
    /// # Panics
    ///
    /// Panics if called before the endpoint has been initialized.
    pub(crate) fn endpoint(&mut self) -> &mut Endpoint {
        self.endpoint
            .as_mut()
            .expect("endpoint not yet initialized")
    }
}

/// Immutable shared parts of the endpoint.
pub(crate) struct EndpointShared {
    /// The UDP socket used for I/O.
    pub(crate) socket: Arc<UdpSocket>,

    /// The local address the endpoint is bound to.
    pub(crate) local_addr: SocketAddr,
}

/// Combined inner state accessible via `Arc`.
pub(crate) struct EndpointInner {
    /// Mutable endpoint state.
    pub(crate) state: Mutex<EndpointState>,

    /// Shared handler state (connections map, pending connect).
    pub(crate) handler_shared: Arc<HandlerShared>,

    /// Immutable shared data.
    pub(crate) shared: EndpointShared,
}

// ---------------------------------------------------------------------------
// TquicEndpoint — public API
// ---------------------------------------------------------------------------

/// A `Send + Sync` async QUIC endpoint handle.
///
/// Wraps a tquic `Endpoint` behind `Arc<Mutex>`. All operations
/// acquire the lock, call tquic methods, and release. An
/// [`EndpointDriver`] Future handles background I/O.
pub struct TquicEndpoint {
    inner: Arc<EndpointInner>,
    incoming_rx: mpsc::Receiver<TquicConnection>,
}

impl TquicEndpoint {
    /// Create a client endpoint bound to the given address.
    pub async fn client(bind: SocketAddr, config: Config) -> Result<Self, AsyncError> {
        create_endpoint(bind, config, false).await
    }

    /// Create a server endpoint bound to the given address.
    pub async fn server(bind: SocketAddr, config: Config) -> Result<Self, AsyncError> {
        create_endpoint(bind, config, true).await
    }

    /// Connect to a remote QUIC server.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<TquicConnection, AsyncError> {
        self.connect_inner(remote, server_name, None, None)
    }

    /// Connect with 0-RTT using a saved session ticket and token.
    pub async fn connect_with_0rtt(
        &self,
        remote: SocketAddr,
        server_name: &str,
        session: &[u8],
        token: &[u8],
    ) -> Result<TquicConnection, AsyncError> {
        self.connect_inner(remote, server_name, Some(session), Some(token))
    }

    /// Accept an incoming connection from a remote client.
    ///
    /// Returns `None` if the endpoint has been closed.
    pub async fn accept(&mut self) -> Option<TquicConnection> {
        self.incoming_rx.recv().await
    }

    /// Return the local address the endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.shared.local_addr
    }

    /// Shut down the endpoint.
    ///
    /// Sets the closed flag, tears down all active connections so
    /// waiters are not left hanging, and wakes the driver.
    pub fn close(&self) {
        let waker = {
            let mut state = self.inner.state.lock().expect("endpoint lock");
            state.closed = true;
            extract_driver_waker(&state)
        };

        self.teardown_connections();
        self.clear_pending_connects();

        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Tear down all active connections so waiters are not left hanging.
    fn teardown_connections(&self) {
        let mut conns = self
            .inner
            .handler_shared
            .connections
            .lock()
            .expect("connections lock");

        for (_index, ci) in conns.drain() {
            Self::force_close_connection(&ci);
        }
    }

    /// Force-close a single connection, waking all pending waiters.
    fn force_close_connection(ci: &ConnectionInner) {
        let mut cs = ci.conn_state.lock().expect("conn_state lock");
        if cs.close_info.is_none() {
            cs.close_info = Some(ConnectionCloseInfo {
                is_app: true,
                error_code: 0,
                reason: b"endpoint closed".to_vec(),
            });
        }
        // Drop stream senders to unblock accept_bi/accept_uni.
        cs.incoming_bi_tx.take();
        cs.incoming_uni_tx.take();
        // Wake all pending stream operations.
        for (_, w) in cs.read_wakers.drain() {
            w.wake();
        }
        for (_, w) in cs.write_wakers.drain() {
            w.wake();
        }
        drop(cs);
        ci.close_notify.notify_waiters();
        ci.dgram_notify.notify_waiters();
    }

    /// Clear pending connect results so `connect()` callers see closure.
    fn clear_pending_connects(&self) {
        self.inner
            .handler_shared
            .pending_connects
            .lock()
            .expect("pending lock")
            .clear();
    }

    /// Internal helper for both `connect` variants.
    fn connect_inner(
        &self,
        remote: SocketAddr,
        server_name: &str,
        session: Option<&[u8]>,
        token: Option<&[u8]>,
    ) -> Result<TquicConnection, AsyncError> {
        let (conn_index, waker) = {
            let mut state = self.inner.state.lock().expect("endpoint lock");
            let local = self.inner.shared.local_addr;

            // connect() returns the connection index and fires
            // on_conn_created synchronously (while we hold the lock).
            let idx = state
                .endpoint()
                .connect(local, remote, Some(server_name), session, token, None)
                .map_err(AsyncError::Tquic)?;

            // Drive the state machine to flush initial packets.
            let _ = state.endpoint().process_connections();

            (idx, extract_driver_waker(&state))
        };
        // Endpoint lock dropped here.

        // Retrieve our result by index -- safe from concurrent connect() races.
        let pending = self
            .inner
            .handler_shared
            .pending_connects
            .lock()
            .expect("pending lock")
            .remove(&conn_index)
            .ok_or(AsyncError::ConnectionClosed)?;

        if let Some(w) = waker {
            w.wake();
        }

        Ok(TquicConnection {
            inner: pending.conn_inner,
            incoming_bi_rx: pending.incoming_bi_rx,
            incoming_uni_rx: pending.incoming_uni_rx,
        })
    }
}

// ---------------------------------------------------------------------------
// UdpSender — PacketSendHandler backed by tokio UdpSocket
// ---------------------------------------------------------------------------

/// Sends outgoing packets via a tokio `UdpSocket`.
struct UdpSender {
    socket: Arc<UdpSocket>,
}

impl PacketSendHandler for UdpSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> crate::Result<usize> {
        let mut sent = 0;
        for (data, info) in pkts {
            match self.socket.try_send_to(data, info.dst) {
                Ok(_) => sent += 1,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    warn!("UDP send error: {e}");
                    break;
                }
            }
        }
        Ok(sent)
    }
}

// ---------------------------------------------------------------------------
// AdapterHandler — TransportHandler impl
// ---------------------------------------------------------------------------

/// Bridges tquic's callback-based `TransportHandler` to async state.
///
/// Holds an `Arc<HandlerShared>` and an `Arc<EndpointInner>` so
/// callbacks can update connection-level async state.
struct AdapterHandler {
    shared: Arc<HandlerShared>,
    endpoint_inner: Arc<EndpointInner>,
    incoming_tx: mpsc::Sender<TquicConnection>,
    is_server: bool,
}

impl AdapterHandler {
    /// Extract the remote address from a connection's path list.
    fn remote_addr_of(conn: &Connection) -> SocketAddr {
        conn.paths_iter()
            .next()
            .map_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)), |ft| ft.remote)
    }
}

impl TransportHandler for AdapterHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let remote = Self::remote_addr_of(conn);

        let (incoming_bi_tx, incoming_bi_rx) = mpsc::channel(INCOMING_STREAM_CAP);
        let (incoming_uni_tx, incoming_uni_rx) = mpsc::channel(INCOMING_STREAM_CAP);

        let conn_inner = Arc::new(ConnectionInner {
            endpoint: Arc::clone(&self.endpoint_inner),
            conn_state: Mutex::new(ConnAsyncState {
                read_wakers: HashMap::new(),
                write_wakers: HashMap::new(),
                close_info: None,
                incoming_bi_tx: Some(incoming_bi_tx),
                incoming_uni_tx: Some(incoming_uni_tx),
                is_established: false,
            }),
            established_notify: Notify::new(),
            close_notify: Notify::new(),
            dgram_notify: Notify::new(),
            index,
            remote_addr: remote,
        });

        self.shared
            .connections
            .lock()
            .expect("connections lock")
            .insert(index, Arc::clone(&conn_inner));

        if self.is_server {
            let tconn = TquicConnection {
                inner: conn_inner,
                incoming_bi_rx,
                incoming_uni_rx,
            };
            if let Err(_e) = self.incoming_tx.try_send(tconn) {
                warn!(
                    "Incoming connection dropped: channel full (capacity {})",
                    INCOMING_CONN_CAP
                );
            }
        } else {
            self.shared
                .pending_connects
                .lock()
                .expect("pending lock")
                .insert(
                    index,
                    PendingConnResult {
                        conn_inner,
                        incoming_bi_rx,
                        incoming_uni_rx,
                    },
                );
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let conns = self.shared.connections.lock().expect("connections lock");
        if let Some(ci) = conns.get(&index) {
            ci.conn_state
                .lock()
                .expect("conn_state lock")
                .is_established = true;
            ci.established_notify.notify_waiters();
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let close_info = build_close_info(conn);
        let ci = self
            .shared
            .connections
            .lock()
            .expect("connections lock")
            .remove(&index);

        if let Some(ci) = ci {
            let mut state = ci.conn_state.lock().expect("conn_state lock");
            state.close_info = Some(close_info);
            state.incoming_bi_tx.take();
            state.incoming_uni_tx.take();
            // Wake all pending stream operations.
            for (_, waker) in state.read_wakers.drain() {
                waker.wake();
            }
            for (_, waker) in state.write_wakers.drain() {
                waker.wake();
            }
            drop(state);
            ci.close_notify.notify_waiters();
            ci.dgram_notify.notify_waiters();
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);

        // Only handle peer-initiated streams here.
        let is_local = (stream_id & 0x1 == 0) != self.is_server;
        if is_local {
            return;
        }

        let conns = self.shared.connections.lock().expect("connections lock");
        let Some(ci) = conns.get(&index) else { return };

        let is_bidi = stream_id & 0x2 == 0;
        let state = ci.conn_state.lock().expect("conn_state lock");

        if is_bidi {
            let send = SendStream::new(stream_id, index, Arc::clone(ci));
            let recv = RecvStream::new(stream_id, index, Arc::clone(ci));
            if let Some(tx) = &state.incoming_bi_tx {
                if let Err(_e) = tx.try_send((send, recv)) {
                    warn!("Incoming bidi stream {stream_id} dropped: channel full");
                }
            }
        } else {
            let recv = RecvStream::new(stream_id, index, Arc::clone(ci));
            if let Some(tx) = &state.incoming_uni_tx {
                if let Err(_e) = tx.try_send(recv) {
                    warn!("Incoming uni stream {stream_id} dropped: channel full");
                }
            }
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        let conns = self.shared.connections.lock().expect("connections lock");
        if let Some(ci) = conns.get(&index) {
            if let Some(waker) = ci
                .conn_state
                .lock()
                .expect("conn_state lock")
                .read_wakers
                .remove(&stream_id)
            {
                waker.wake();
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        let conns = self.shared.connections.lock().expect("connections lock");
        if let Some(ci) = conns.get(&index) {
            if let Some(waker) = ci
                .conn_state
                .lock()
                .expect("conn_state lock")
                .write_wakers
                .remove(&stream_id)
            {
                waker.wake();
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        let conns = self.shared.connections.lock().expect("connections lock");
        if let Some(ci) = conns.get(&index) {
            let mut state = ci.conn_state.lock().expect("conn_state lock");
            if let Some(waker) = state.read_wakers.remove(&stream_id) {
                waker.wake();
            }
            if let Some(waker) = state.write_wakers.remove(&stream_id) {
                waker.wake();
            }
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {
        // Session ticket storage for 0-RTT; not yet implemented.
    }

    fn on_dgram_readable(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let conns = self.shared.connections.lock().expect("connections lock");
        if let Some(ci) = conns.get(&index) {
            ci.dgram_notify.notify_waiters();
        }
    }
}

/// Build a `ConnectionCloseInfo` from a connection's error state.
fn build_close_info(conn: &Connection) -> ConnectionCloseInfo {
    conn.peer_error().or(conn.local_error()).map_or_else(
        || ConnectionCloseInfo {
            is_app: false,
            error_code: 0,
            reason: Vec::new(),
        },
        |err| ConnectionCloseInfo {
            is_app: err.is_app,
            error_code: err.error_code,
            reason: err.reason.clone(),
        },
    )
}

// ---------------------------------------------------------------------------
// EndpointDriver — Future that drives I/O
// ---------------------------------------------------------------------------

/// Background driver Future that reads UDP packets, processes
/// the tquic state machine, and manages timers.
///
/// Spawned as a tokio task. Wakes when the socket is readable,
/// a timer fires, or user code signals via the driver waker.
struct EndpointDriver {
    inner: Arc<EndpointInner>,
    recv_buf: Vec<u8>,
    closed: Arc<AtomicBool>,
    /// Reusable timer — reset each poll instead of spawning new tasks.
    timer: Pin<Box<tokio::time::Sleep>>,
}

impl Future for EndpointDriver {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(());
        }

        let driver = &mut *self;
        let keep_going = driver.poll_work_loop(cx);

        // Re-check: poll_work_loop may have set closed.
        if driver.closed.load(Ordering::Relaxed) {
            return Poll::Ready(());
        }

        if keep_going {
            // More work pending — wake immediately to avoid stall.
            cx.waker().wake_by_ref();
        }

        // Reset timer to the endpoint's next timeout.
        let dur = {
            let mut state = driver.inner.state.lock().expect("endpoint lock");
            state.endpoint().timeout().unwrap_or(DEFAULT_IDLE_TIMEOUT)
        };
        driver
            .timer
            .as_mut()
            .reset(tokio::time::Instant::now() + dur);
        // Poll the timer to register the waker.
        let _ = driver.timer.as_mut().poll(cx);

        Poll::Pending
    }
}

impl EndpointDriver {
    /// Run the I/O + process loop up to `IO_LOOP_BOUND` iterations.
    ///
    /// Returns `true` if the loop exited due to `IO_LOOP_BOUND`
    /// (more work pending), signalling the caller to self-wake.
    fn poll_work_loop(&mut self, cx: &mut Context<'_>) -> bool {
        let mut work_done = true;
        let mut iterations = 0;

        while work_done && iterations < IO_LOOP_BOUND {
            work_done = false;
            iterations += 1;

            if self.poll_recv_udp(cx) {
                work_done = true;
            }

            let mut state = self.inner.state.lock().expect("endpoint lock");
            state.driver_waker = Some(cx.waker().clone());

            if state.closed {
                self.closed.store(true, Ordering::Relaxed);
                return false;
            }

            let _ = state.endpoint().process_connections();

            if self.poll_expired_timeout(&mut state) {
                work_done = true;
            }
        }

        // Cut short by IO_LOOP_BOUND with work still pending.
        work_done && iterations >= IO_LOOP_BOUND
    }

    /// Check if the endpoint timeout has expired and handle it.
    ///
    /// Returns `true` if a timeout fired and was processed.
    fn poll_expired_timeout(&self, state: &mut EndpointState) -> bool {
        if let Some(timeout) = state.endpoint().timeout() {
            if timeout.is_zero() {
                state.endpoint().on_timeout(Instant::now());
                let _ = state.endpoint().process_connections();
                return true;
            }
        }
        false
    }

    /// Try to receive UDP packets from the socket (non-blocking).
    ///
    /// Returns `true` if at least one packet was received.
    fn poll_recv_udp(&mut self, cx: &mut Context<'_>) -> bool {
        let mut received = false;
        let local_addr = self.inner.shared.local_addr;

        loop {
            let mut read_buf = tokio::io::ReadBuf::new(&mut self.recv_buf);
            match self.inner.shared.socket.poll_recv_from(cx, &mut read_buf) {
                Poll::Ready(Ok(src)) => {
                    let n = read_buf.filled().len();
                    let info = PacketInfo {
                        src,
                        dst: local_addr,
                        time: Instant::now(),
                    };
                    let mut state = self.inner.state.lock().expect("endpoint lock");
                    let _ = state.endpoint().recv(&mut self.recv_buf[..n], &info);
                    received = true;
                }
                // Spurious ICMP errors on UDP; ignore per QUIC spec.
                Poll::Ready(Err(ref e))
                    if e.kind() == std::io::ErrorKind::ConnectionReset
                        || e.kind() == std::io::ErrorKind::ConnectionRefused =>
                {
                    continue;
                }
                Poll::Ready(Err(e)) => {
                    warn!("UDP recv error: {e}");
                    break;
                }
                Poll::Pending => break,
            }
        }
        received
    }
}

// ---------------------------------------------------------------------------
// Endpoint creation
// ---------------------------------------------------------------------------

/// Create and initialize a QUIC endpoint (client or server).
async fn create_endpoint(
    bind: SocketAddr,
    config: Config,
    is_server: bool,
) -> Result<TquicEndpoint, AsyncError> {
    let std_socket = bind_udp_socket(bind)?;
    let local_addr = std_socket
        .local_addr()
        .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;

    let tokio_socket =
        UdpSocket::from_std(std_socket).map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
    let socket = Arc::new(tokio_socket);

    let (incoming_tx, incoming_rx) = mpsc::channel(INCOMING_CONN_CAP);

    let handler_shared = Arc::new(HandlerShared {
        connections: Mutex::new(HashMap::new()),
        pending_connects: Mutex::new(HashMap::new()),
    });

    // We need `Arc<EndpointInner>` for the handler, but the handler
    // must be passed to `Endpoint::new`. Break the cycle by starting
    // with `endpoint: None` and filling it in immediately after.
    let sender: SharedRc<dyn PacketSendHandler + Send + Sync> = SharedRc::new(UdpSender {
        socket: Arc::clone(&socket),
    });

    let inner = Arc::new(EndpointInner {
        state: Mutex::new(EndpointState {
            endpoint: None, // filled in below
            driver_waker: None,
            closed: false,
        }),
        handler_shared: Arc::clone(&handler_shared),
        shared: EndpointShared {
            socket: Arc::clone(&socket),
            local_addr,
        },
    });

    let handler = AdapterHandler {
        shared: Arc::clone(&handler_shared),
        endpoint_inner: Arc::clone(&inner),
        incoming_tx,
        is_server,
    };

    let endpoint = Endpoint::new(Box::new(config), is_server, Box::new(handler), sender);
    inner.state.lock().expect("endpoint lock").endpoint = Some(endpoint);

    let closed = Arc::new(AtomicBool::new(false));
    let driver = EndpointDriver {
        inner: Arc::clone(&inner),
        recv_buf: vec![0u8; RECV_BUF_SIZE],
        closed,
        timer: Box::pin(tokio::time::sleep(DEFAULT_IDLE_TIMEOUT)),
    };
    tokio::spawn(driver);

    Ok(TquicEndpoint { inner, incoming_rx })
}

/// Bind a non-blocking UDP socket.
fn bind_udp_socket(bind: SocketAddr) -> Result<std::net::UdpSocket, AsyncError> {
    let socket =
        std::net::UdpSocket::bind(bind).map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
    Ok(socket)
}

/// Extract the driver waker for waking outside the lock.
pub(crate) fn extract_driver_waker(state: &EndpointState) -> Option<Waker> {
    state.driver_waker.clone()
}

/// Copy the essential fields of `ConnectionStats` into an owned value.
///
/// `ConnectionStats` derives `Clone`, so we simply clone it.
pub(crate) fn copy_connection_stats(conn: &Connection) -> crate::connection::ConnectionStats {
    conn.stats().clone()
}
