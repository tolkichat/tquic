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

//! Single-owner reactor for the tokio adapter.
//!
//! One tokio task exclusively owns the `Endpoint`. All user-facing
//! operations communicate through bounded MPSC channels with oneshot
//! response senders. Zero mutex contention.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use log::*;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use super::cmd::{
    ConnHandle, ControlCmd, DataCmd, IncomingBiStream, IncomingUniStream, OpenBiResult,
    OpenUniResult, SharedConnState,
};
use super::error::AsyncError;
use super::reactor_handler::{HandlerEvent, ReactorHandler};
use super::shared::{SharedInner, SharedState};
use crate::{Config, Endpoint, PacketInfo, PacketSendHandler, SharedRc};

/// Channel capacity for control commands.
const CONTROL_CHAN_CAP: usize = 256;

/// Channel capacity for data commands.
const DATA_CHAN_CAP: usize = 4096;

/// Maximum data commands to batch per select iteration.
const DATA_BATCH_LIMIT: usize = 64;

/// Maximum UDP receive buffer size.
const RECV_BUF_SIZE: usize = 65536;

/// Fallback timer when no pending timeouts.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_millis(100);

/// Channel capacity for incoming connections (server).
const INCOMING_CONN_CAP: usize = 256;

/// Channel capacity for incoming streams per connection.
const INCOMING_STREAM_CAP: usize = 256;

// ---------------------------------------------------------------------------
// Per-connection state
// ---------------------------------------------------------------------------

/// Per-connection async state managed by the reactor.
pub(crate) struct ReactorConnState {
    /// Shared state visible to user-facing connection handles.
    pub(crate) shared: Arc<SharedConnState>,
    /// Remote peer address.
    pub(crate) remote_addr: SocketAddr,
    /// Pending datagram recv operations.
    pub(crate) pending_dgram_reads: Vec<oneshot::Sender<Result<Bytes, AsyncError>>>,
    /// Sender for incoming bidi streams (server-side).
    pub(crate) incoming_bi_tx: Option<mpsc::Sender<IncomingBiStream>>,
    /// Sender for incoming uni streams (server-side).
    pub(crate) incoming_uni_tx: Option<mpsc::Sender<IncomingUniStream>>,
}

/// Close information for a connection.
#[derive(Clone, Debug)]
pub(crate) struct CloseInfo {
    /// Whether the close was initiated by the application layer.
    pub(crate) is_app: bool,
    /// The error code carried in the CONNECTION_CLOSE frame.
    pub(crate) error_code: u64,
    /// Human-readable reason phrase.
    pub(crate) reason: Vec<u8>,
}

// ---------------------------------------------------------------------------
// UdpSender
// ---------------------------------------------------------------------------

/// Sends outgoing packets via a tokio UdpSocket.
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
// Reactor
// ---------------------------------------------------------------------------

/// The single-owner reactor.
///
/// Wraps the tquic `Endpoint` in `SharedState` (`Arc<Mutex<SharedInner>>`).
/// Both the reactor and user-facing stream handles access the endpoint
/// through the Mutex. Stream I/O goes directly through the Mutex;
/// the reactor handles UDP I/O, timers, commands, and handler events.
pub(crate) struct Reactor {
    /// The tquic endpoint behind shared Mutex.
    shared: SharedState,
    /// UDP socket for I/O.
    socket: Arc<UdpSocket>,
    /// Local address.
    local_addr: SocketAddr,
    /// Control command receiver.
    control_rx: mpsc::Receiver<ControlCmd>,
    /// Data command receiver.
    data_rx: mpsc::Receiver<DataCmd>,
    /// Handler event receiver (from TransportHandler callbacks).
    event_rx: mpsc::UnboundedReceiver<HandlerEvent>,
    /// Per-connection state.
    connections: HashMap<u64, ReactorConnState>,
    /// Pending connect results (conn_index -> oneshot).
    pending_connects: HashMap<u64, oneshot::Sender<Result<ConnHandle, AsyncError>>>,
    /// Whether this is a server.
    is_server: bool,
    /// Sender for incoming connections (server mode).
    incoming_conn_tx: Option<mpsc::Sender<ConnHandle>>,
    /// Receive buffer.
    recv_buf: Vec<u8>,
    /// Notify handle: stream handles wake the driver after writes.
    driver_notify: Arc<Notify>,
}

/// Channels returned when creating a reactor, for user-facing handles.
pub(crate) struct ReactorChannels {
    /// Sender for control-plane commands.
    pub(crate) control_tx: mpsc::Sender<ControlCmd>,
    /// Sender for data-plane commands.
    pub(crate) data_tx: mpsc::Sender<DataCmd>,
    /// Receiver for incoming connections (server mode only).
    pub(crate) incoming_conn_rx: Option<mpsc::Receiver<ConnHandle>>,
    /// Shared endpoint state for direct-call stream I/O.
    pub(crate) shared: SharedState,
    /// Notify handle: stream handles wake the driver after writes.
    pub(crate) driver_notify: Arc<Notify>,
}

impl Reactor {
    /// Create a new reactor and return the channel handles.
    pub(crate) fn new(
        bind: SocketAddr,
        config: Config,
        is_server: bool,
    ) -> Result<(Self, ReactorChannels), AsyncError> {
        let (socket, local_addr) = Self::bind_socket(bind)?;
        let socket = Arc::new(socket);

        let (control_tx, control_rx) = mpsc::channel(CONTROL_CHAN_CAP);
        let (data_tx, data_rx) = mpsc::channel(DATA_CHAN_CAP);
        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let (incoming_conn_tx, incoming_conn_rx) = if is_server {
            let (tx, rx) = mpsc::channel(INCOMING_CONN_CAP);
            (Some(tx), Some(rx))
        } else {
            (None, None)
        };

        let handler = ReactorHandler::new(event_tx, is_server);
        let sender: SharedRc<dyn PacketSendHandler + Send + Sync> = SharedRc::new(UdpSender {
            socket: Arc::clone(&socket),
        });
        let endpoint = Endpoint::new(Box::new(config), is_server, Box::new(handler), sender);

        let shared: SharedState = Arc::new(std::sync::Mutex::new(SharedInner::new(endpoint)));
        let driver_notify = Arc::new(Notify::new());

        let reactor = Self {
            shared: Arc::clone(&shared),
            socket,
            local_addr,
            control_rx,
            data_rx,
            event_rx,
            connections: HashMap::new(),
            pending_connects: HashMap::new(),
            is_server,
            incoming_conn_tx,
            recv_buf: vec![0u8; RECV_BUF_SIZE],
            driver_notify: Arc::clone(&driver_notify),
        };

        let channels = ReactorChannels {
            control_tx,
            data_tx,
            incoming_conn_rx,
            shared,
            driver_notify,
        };

        Ok((reactor, channels))
    }

    /// Return the local address the reactor is bound to.
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Bind a non-blocking UDP socket and return it with its local address.
    fn bind_socket(bind: SocketAddr) -> Result<(UdpSocket, SocketAddr), AsyncError> {
        let std_socket = std::net::UdpSocket::bind(bind)
            .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
        std_socket
            .set_nonblocking(true)
            .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
        let local_addr = std_socket
            .local_addr()
            .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
        let tokio_socket = UdpSocket::from_std(std_socket)
            .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
        Ok((tokio_socket, local_addr))
    }

    /// Run the reactor loop. This is the entry point for `tokio::spawn`.
    pub(crate) async fn run(mut self) {
        let timer = tokio::time::sleep(DEFAULT_IDLE_TIMEOUT);
        tokio::pin!(timer);

        loop {
            tokio::select! {
                biased;

                Some(cmd) = self.control_rx.recv() => {
                    if self.handle_control(cmd) {
                        break; // Shutdown
                    }
                    self.process_and_dispatch();
                }

                result = self.socket.recv_from(&mut self.recv_buf) => {
                    self.handle_udp_recv(result);
                    self.drain_udp_recv();
                    self.process_and_dispatch();
                }

                () = self.driver_notify.notified() => {
                    // Stream handles already wrote data via Mutex.
                    // Driver just needs to call process_connections
                    // to generate/send packets.
                    self.process_and_dispatch();
                }

                Some(cmd) = self.data_rx.recv() => {
                    self.handle_data(cmd);
                    self.batch_data_commands();
                    self.process_and_dispatch();
                }

                () = &mut timer => {
                    {
                        let mut inner = self.shared.lock()
                            .expect("shared state poisoned");
                        inner.endpoint.on_timeout(Instant::now());
                    }
                    self.process_and_dispatch();
                }
            }

            // Reset timer.
            let dur = self
                .shared
                .lock()
                .expect("shared state poisoned")
                .endpoint
                .timeout()
                .unwrap_or(DEFAULT_IDLE_TIMEOUT);
            timer.as_mut().reset(tokio::time::Instant::now() + dur);
        }

        self.shutdown_all();
    }

    /// Process a single UDP recv result.
    fn handle_udp_recv(&mut self, result: Result<(usize, SocketAddr), std::io::Error>) {
        if let Ok((n, src)) = result {
            let info = PacketInfo {
                src,
                dst: self.local_addr,
                time: Instant::now(),
            };
            let mut inner = self.shared.lock().expect("shared state poisoned");
            let _ = inner.endpoint.recv(&mut self.recv_buf[..n], &info);
        }
    }

    /// Drain additional data commands without yielding.
    fn batch_data_commands(&mut self) {
        for _ in 0..DATA_BATCH_LIMIT - 1 {
            match self.data_rx.try_recv() {
                Ok(cmd) => self.handle_data(cmd),
                Err(_) => break,
            }
        }
    }

    /// Handle a control command. Returns `true` for Shutdown.
    fn handle_control(&mut self, cmd: ControlCmd) -> bool {
        match cmd {
            ControlCmd::Shutdown => return true,
            ControlCmd::Connect {
                remote,
                server_name,
                session,
                token,
                tx,
            } => {
                self.handle_connect(
                    remote,
                    &server_name,
                    session.as_deref(),
                    token.as_deref(),
                    tx,
                );
            }
            ControlCmd::OpenBi { conn_index, tx } => {
                self.handle_open_bi(conn_index, tx);
            }
            ControlCmd::OpenUni { conn_index, tx } => {
                self.handle_open_uni(conn_index, tx);
            }
            ControlCmd::Close {
                conn_index,
                error_code,
                reason,
            } => {
                self.handle_close(conn_index, error_code, &reason);
            }
            ControlCmd::Stats { conn_index, tx } => {
                self.handle_stats(conn_index, tx);
            }
        }
        false
    }

    /// Handle a data command.
    fn handle_data(&mut self, cmd: DataCmd) {
        match cmd {
            DataCmd::StreamShutdown {
                conn_index,
                stream_id,
                direction,
                error_code,
            } => self.handle_stream_shutdown(conn_index, stream_id, direction, error_code),
            DataCmd::DgramSend {
                conn_index,
                data,
                tx,
            } => self.handle_dgram_send(conn_index, data, tx),
            DataCmd::DgramRecv { conn_index, tx } => {
                self.handle_dgram_recv(conn_index, tx);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Control-plane command handlers
// ---------------------------------------------------------------------------

impl Reactor {
    /// Initiate a connection to a remote peer.
    fn handle_connect(
        &mut self,
        remote: SocketAddr,
        server_name: &str,
        session: Option<&[u8]>,
        token: Option<&[u8]>,
        tx: oneshot::Sender<Result<ConnHandle, AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        match inner.endpoint.connect(
            self.local_addr,
            remote,
            Some(server_name),
            session,
            token,
            None,
        ) {
            Ok(idx) => {
                drop(inner);
                self.pending_connects.insert(idx, tx);
            }
            Err(e) => {
                drop(inner);
                let _ = tx.send(Err(AsyncError::Tquic(e)));
            }
        }
    }

    /// Open a new bidirectional stream on a connection.
    fn handle_open_bi(
        &mut self,
        conn_index: u64,
        tx: oneshot::Sender<Result<OpenBiResult, AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let sid = match inner.endpoint.conn_get_mut(conn_index) {
            Some(conn) => match conn.stream_bidi_new(0, false) {
                Ok(s) => s,
                Err(e) => {
                    drop(inner);
                    let _ = tx.send(Err(AsyncError::Tquic(e)));
                    return;
                }
            },
            None => {
                drop(inner);
                let _ = tx.send(Err(AsyncError::ConnectionClosed));
                return;
            }
        };
        drop(inner);
        let _ = tx.send(Ok(OpenBiResult {
            send_id: sid,
            recv_id: sid,
        }));
    }

    /// Open a new unidirectional stream on a connection.
    fn handle_open_uni(
        &mut self,
        conn_index: u64,
        tx: oneshot::Sender<Result<OpenUniResult, AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let sid = match inner.endpoint.conn_get_mut(conn_index) {
            Some(conn) => match conn.stream_uni_new(0, false) {
                Ok(s) => s,
                Err(e) => {
                    drop(inner);
                    let _ = tx.send(Err(AsyncError::Tquic(e)));
                    return;
                }
            },
            None => {
                drop(inner);
                let _ = tx.send(Err(AsyncError::ConnectionClosed));
                return;
            }
        };
        drop(inner);
        let _ = tx.send(Ok(OpenUniResult { stream_id: sid }));
    }

    /// Close a connection.
    fn handle_close(&mut self, conn_index: u64, error_code: u64, reason: &[u8]) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        if let Some(conn) = inner.endpoint.conn_get_mut(conn_index) {
            let _ = conn.close(true, error_code, reason);
        }
    }

    /// Retrieve connection statistics.
    fn handle_stats(
        &mut self,
        conn_index: u64,
        tx: oneshot::Sender<Result<crate::connection::ConnectionStats, AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let result = inner
            .endpoint
            .conn_get_mut(conn_index)
            .ok_or(AsyncError::ConnectionClosed)
            .map(|conn| conn.stats().clone());
        drop(inner);
        let _ = tx.send(result);
    }
}

// ---------------------------------------------------------------------------
// Data-plane command handlers
// ---------------------------------------------------------------------------

impl Reactor {
    /// Shut down one direction of a stream.
    fn handle_stream_shutdown(
        &mut self,
        conn_index: u64,
        stream_id: u64,
        direction: crate::Shutdown,
        error_code: u64,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        if let Some(conn) = inner.endpoint.conn_get_mut(conn_index) {
            let _ = conn.stream_shutdown(stream_id, direction, error_code);
        }
    }

    /// Send an unreliable datagram.
    fn handle_dgram_send(
        &mut self,
        conn_index: u64,
        data: Bytes,
        tx: oneshot::Sender<Result<(), AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let result = inner
            .endpoint
            .conn_get_mut(conn_index)
            .ok_or(AsyncError::ConnectionClosed)
            .and_then(|conn| conn.dgram_send(data).map_err(AsyncError::Tquic));
        drop(inner);
        let _ = tx.send(result);
    }

    /// Receive an unreliable datagram, parking if none available.
    fn handle_dgram_recv(
        &mut self,
        conn_index: u64,
        tx: oneshot::Sender<Result<Bytes, AsyncError>>,
    ) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let conn = match inner.endpoint.conn_get_mut(conn_index) {
            Some(c) => c,
            None => {
                drop(inner);
                let _ = tx.send(Err(AsyncError::ConnectionClosed));
                return;
            }
        };
        match conn.dgram_recv() {
            Ok(data) => {
                drop(inner);
                let _ = tx.send(Ok(data));
            }
            Err(crate::Error::Done) => {
                drop(inner);
                // No datagram: park the recv.
                if let Some(cs) = self.connections.get_mut(&conn_index) {
                    cs.pending_dgram_reads.push(tx);
                } else {
                    let _ = tx.send(Err(AsyncError::ConnectionClosed));
                }
            }
            Err(e) => {
                drop(inner);
                let _ = tx.send(Err(AsyncError::Tquic(e)));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// UDP I/O helpers
// ---------------------------------------------------------------------------

impl Reactor {
    /// Drain non-blocking UDP receives.
    fn drain_udp_recv(&mut self) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        loop {
            match self.socket.try_recv_from(&mut self.recv_buf) {
                Ok((n, src)) => {
                    let info = PacketInfo {
                        src,
                        dst: self.local_addr,
                        time: Instant::now(),
                    };
                    let _ = inner.endpoint.recv(&mut self.recv_buf[..n], &info);
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
    }

    /// Process connections and dispatch handler events.
    fn process_and_dispatch(&mut self) {
        {
            let mut inner = self.shared.lock().expect("shared state poisoned");
            let _ = inner.endpoint.process_connections();
        }
        self.drain_handler_events();
    }

    /// Process all pending handler events.
    fn drain_handler_events(&mut self) {
        while let Ok(event) = self.event_rx.try_recv() {
            self.dispatch_event(event);
        }
    }
}

// ---------------------------------------------------------------------------
// Handler event dispatch
// ---------------------------------------------------------------------------

impl Reactor {
    /// Handle a single handler event.
    fn dispatch_event(&mut self, event: HandlerEvent) {
        match event {
            HandlerEvent::ConnCreated { index, remote } => {
                self.on_conn_created(index, remote);
            }
            HandlerEvent::ConnEstablished { index } => {
                self.on_conn_established(index);
            }
            HandlerEvent::ConnClosed {
                index,
                is_app,
                error_code,
                reason,
            } => {
                self.on_conn_closed(index, is_app, error_code, reason);
            }
            HandlerEvent::StreamCreated { index, stream_id } => {
                self.on_stream_created(index, stream_id);
            }
            HandlerEvent::StreamReadable { index, stream_id } => {
                self.on_stream_readable(index, stream_id);
            }
            HandlerEvent::StreamWritable { index, stream_id } => {
                self.on_stream_writable(index, stream_id);
            }
            HandlerEvent::StreamClosed { index, stream_id } => {
                self.on_stream_closed(index, stream_id);
            }
            HandlerEvent::DgramReadable { index } => {
                self.on_dgram_readable(index);
            }
            HandlerEvent::NewToken { .. } => {
                // 0-RTT session ticket storage, not yet implemented.
            }
        }
    }

    /// Handle a new connection being created.
    fn on_conn_created(&mut self, index: u64, remote: SocketAddr) {
        let shared = Arc::new(SharedConnState {
            is_established: AtomicBool::new(false),
            established: Notify::new(),
            closed: Notify::new(),
            close_info: std::sync::Mutex::new(None),
        });

        let (bi_tx, bi_rx) = mpsc::channel(INCOMING_STREAM_CAP);
        let (uni_tx, uni_rx) = mpsc::channel(INCOMING_STREAM_CAP);

        let state = ReactorConnState {
            shared: Arc::clone(&shared),
            remote_addr: remote,
            pending_dgram_reads: Vec::new(),
            incoming_bi_tx: Some(bi_tx),
            incoming_uni_tx: Some(uni_tx),
        };

        self.connections.insert(index, state);
        self.deliver_conn_handle(index, remote, shared, bi_rx, uni_rx);
    }

    /// Deliver the connection handle to either pending connects or incoming channel.
    fn deliver_conn_handle(
        &mut self,
        index: u64,
        remote: SocketAddr,
        shared: Arc<SharedConnState>,
        incoming_bi_rx: mpsc::Receiver<IncomingBiStream>,
        incoming_uni_rx: mpsc::Receiver<IncomingUniStream>,
    ) {
        let handle = ConnHandle {
            conn_index: index,
            remote_addr: remote,
            shared,
            incoming_bi_rx,
            incoming_uni_rx,
        };

        if self.is_server {
            if let Some(tx) = &self.incoming_conn_tx {
                if tx.try_send(handle).is_err() {
                    warn!("incoming connection dropped: channel full");
                }
            }
        } else if let Some(tx) = self.pending_connects.remove(&index) {
            let _ = tx.send(Ok(handle));
        }
    }

    /// Handle a connection handshake completing.
    fn on_conn_established(&mut self, index: u64) {
        if let Some(cs) = self.connections.get(&index) {
            cs.shared.is_established.store(true, Ordering::Release);
            cs.shared.established.notify_waiters();
        }
    }

    /// Handle a connection being closed.
    fn on_conn_closed(&mut self, index: u64, is_app: bool, error_code: u64, reason: Vec<u8>) {
        let Some(mut cs) = self.connections.remove(&index) else {
            return;
        };
        let info = CloseInfo {
            is_app,
            error_code,
            reason,
        };
        *cs.shared.close_info.lock().expect("close_info lock") = Some(info);
        Self::fail_pending_ops(&mut cs);

        // Wake all stream wakers so blocked reads/writes return errors.
        let wakers = self
            .shared
            .lock()
            .expect("shared state poisoned")
            .remove_conn_wakers(index);
        for w in wakers {
            w.wake();
        }

        cs.incoming_bi_tx.take();
        cs.incoming_uni_tx.take();
        cs.shared.closed.notify_waiters();
    }

    /// Fail all pending datagram operations on a connection.
    fn fail_pending_ops(cs: &mut ReactorConnState) {
        for tx in cs.pending_dgram_reads.drain(..) {
            let _ = tx.send(Err(AsyncError::ConnectionClosed));
        }
    }
}

// ---------------------------------------------------------------------------
// Stream event handlers
// ---------------------------------------------------------------------------

impl Reactor {
    /// Handle a peer-initiated stream being created.
    fn on_stream_created(&mut self, index: u64, stream_id: u64) {
        let is_bidi = stream_id & 0x2 == 0;

        if is_bidi {
            self.create_incoming_bidi(index, stream_id);
        } else {
            self.create_incoming_uni(index, stream_id);
        }
    }

    /// Deliver an incoming bidirectional stream (IDs only, no slots).
    fn create_incoming_bidi(&mut self, index: u64, stream_id: u64) {
        let Some(cs) = self.connections.get_mut(&index) else {
            return;
        };
        let incoming = IncomingBiStream {
            send_id: stream_id,
            recv_id: stream_id,
        };
        if let Some(tx) = &cs.incoming_bi_tx {
            if tx.try_send(incoming).is_err() {
                warn!("incoming bidi stream {stream_id} dropped: channel full");
            }
        }
    }

    /// Deliver an incoming unidirectional stream (ID only, no slots).
    fn create_incoming_uni(&mut self, index: u64, stream_id: u64) {
        let Some(cs) = self.connections.get_mut(&index) else {
            return;
        };
        let incoming = IncomingUniStream { stream_id };
        if let Some(tx) = &cs.incoming_uni_tx {
            if tx.try_send(incoming).is_err() {
                warn!("incoming uni stream {stream_id} dropped: channel full");
            }
        }
    }

    /// Wake the read waker when the stream becomes readable.
    fn on_stream_readable(&mut self, index: u64, stream_id: u64) {
        let waker = self
            .shared
            .lock()
            .expect("shared state poisoned")
            .take_read_waker(index, stream_id);
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Wake the write waker when the stream becomes writable.
    fn on_stream_writable(&mut self, index: u64, stream_id: u64) {
        let waker = self
            .shared
            .lock()
            .expect("shared state poisoned")
            .take_write_waker(index, stream_id);
        if let Some(w) = waker {
            w.wake();
        }
    }

    /// Wake both wakers when a stream is closed.
    fn on_stream_closed(&mut self, index: u64, stream_id: u64) {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let ww = inner.take_write_waker(index, stream_id);
        let rw = inner.take_read_waker(index, stream_id);
        drop(inner);
        if let Some(w) = ww {
            w.wake();
        }
        if let Some(w) = rw {
            w.wake();
        }
    }

    /// Retry parked datagram reads when datagrams arrive.
    fn on_dgram_readable(&mut self, index: u64) {
        let Some(cs) = self.connections.get_mut(&index) else {
            return;
        };
        if cs.pending_dgram_reads.is_empty() {
            return;
        }

        let pending = std::mem::take(&mut cs.pending_dgram_reads);
        let remaining = self.satisfy_dgram_reads(index, pending);

        if let Some(cs) = self.connections.get_mut(&index) {
            cs.pending_dgram_reads = remaining;
        }
    }

    /// Try to satisfy pending datagram read operations.
    ///
    /// Returns any operations that could not be satisfied.
    fn satisfy_dgram_reads(
        &mut self,
        index: u64,
        pending: Vec<oneshot::Sender<Result<Bytes, AsyncError>>>,
    ) -> Vec<oneshot::Sender<Result<Bytes, AsyncError>>> {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let conn = match inner.endpoint.conn_get_mut(index) {
            Some(c) => c,
            None => return Vec::new(),
        };
        let mut remaining = Vec::new();
        for tx in pending {
            match conn.dgram_recv() {
                Ok(data) => {
                    let _ = tx.send(Ok(data));
                }
                Err(crate::Error::Done) => {
                    remaining.push(tx);
                    break; // No more datagrams.
                }
                Err(e) => {
                    let _ = tx.send(Err(AsyncError::Tquic(e)));
                }
            }
        }
        remaining
    }
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

impl Reactor {
    /// Shutdown: fail all pending operations and wake all wakers.
    fn shutdown_all(&mut self) {
        // Collect all connection indices before draining.
        let indices: Vec<u64> = self.connections.keys().copied().collect();

        // Wake all stream wakers across all connections.
        {
            let mut inner = self.shared.lock().expect("shared state poisoned");
            for &idx in &indices {
                let _ = inner.remove_conn_wakers(idx);
            }
        }

        for (_, mut cs) in self.connections.drain() {
            Self::fail_pending_ops(&mut cs);
            cs.shared.closed.notify_waiters();
        }
        for (_, tx) in self.pending_connects.drain() {
            let _ = tx.send(Err(AsyncError::ConnectionClosed));
        }
        self.shared
            .lock()
            .expect("shared state poisoned")
            .endpoint
            .close(true);
    }
}
