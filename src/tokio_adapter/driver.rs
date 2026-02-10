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

//! Driver event loop for the tokio async adapter.
//!
//! The driver runs on a `tokio::task::LocalSet` because tquic's
//! `Endpoint` and `Connection` are `!Send`. It bridges tquic's
//! callback-based `TransportHandler` to async channels.
//!
//! # Architecture
//!
//! The `DriverHandler` (which implements `TransportHandler`) is shared
//! between the tquic `Endpoint` (via `HandlerShim`) and the event loop
//! through `Rc<RefCell<>>`. This is safe because everything runs on a
//! single-threaded `LocalSet`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::*;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, watch, Notify};

use crate::connection::Connection;
use crate::{Endpoint, PacketInfo, PacketSendHandler, TransportHandler};

use super::connection::{ConnCmd, ConnectionCloseInfo, TquicConnection};
use super::endpoint::{EndpointCmd, TquicEndpoint};
use super::error::AsyncError;
use super::stream::{RecvStream, SendStream, StreamCmd};

/// Maximum UDP receive buffer size (64 KiB).
const RECV_BUF_SIZE: usize = 65536;

/// Channel capacity for per-connection command channels.
const CONN_CMD_CAP: usize = 256;

/// Channel capacity for per-connection stream command channels.
const STREAM_CMD_CAP: usize = 512;

/// Channel capacity for incoming streams on a connection.
const INCOMING_STREAM_CAP: usize = 64;

/// Default fallback timeout when the endpoint reports no pending timers.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// Per-connection state tracked by the driver
// ---------------------------------------------------------------------------

/// Per-connection state tracked by the driver.
struct ConnectionState {
    /// Notified when the handshake completes.
    established: Arc<Notify>,

    /// Sender for connection close information.
    close_tx: watch::Sender<Option<ConnectionCloseInfo>>,

    /// Receiver for stream-level commands from stream handles.
    stream_cmd_rx: mpsc::Receiver<StreamCmd>,

    /// Receiver for connection-level commands from the handle.
    conn_cmd_rx: mpsc::Receiver<ConnCmd>,

    /// Per-stream readable notifications.
    stream_readables: HashMap<u64, Arc<Notify>>,

    /// Per-stream writable notifications.
    stream_writables: HashMap<u64, Arc<Notify>>,

    /// Sender for incoming bidirectional streams.
    incoming_bi_tx: mpsc::Sender<(SendStream, RecvStream)>,

    /// Sender for incoming unidirectional streams.
    incoming_uni_tx: mpsc::Sender<RecvStream>,

    /// Sender for stream commands (cloned into new stream handles).
    stream_cmd_tx: mpsc::Sender<StreamCmd>,

    /// Remote peer address for this connection.
    remote_addr: SocketAddr,
}

// ---------------------------------------------------------------------------
// UdpSender - PacketSendHandler backed by a tokio UdpSocket
// ---------------------------------------------------------------------------

/// Sends outgoing packets via a tokio `UdpSocket`.
///
/// Uses `Rc` because tquic requires `Rc<dyn PacketSendHandler>`.
struct UdpSender {
    socket: Rc<UdpSocket>,
}

impl PacketSendHandler for UdpSender {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> crate::Result<usize> {
        let mut sent = 0;
        for (data, info) in pkts {
            match self.socket.try_send_to(data, info.dst) {
                Ok(_) => sent += 1,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break;
                }
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
// DriverHandler - TransportHandler state behind Rc<RefCell<>>
// ---------------------------------------------------------------------------

/// Bridges tquic `TransportHandler` callbacks to per-connection async state.
struct DriverHandler {
    /// Per-connection state, keyed by tquic connection index.
    conns: HashMap<u64, ConnectionState>,

    /// Channel for delivering new server-side connections to the endpoint.
    incoming_tx: mpsc::Sender<TquicConnection>,

    /// Whether this endpoint is a server.
    is_server: bool,

    /// Pending client-side connect requests awaiting `on_conn_created`.
    ///
    /// The driver pushes a sender here before calling `endpoint.connect()`.
    /// `on_conn_created` pops it and sends back the `TquicConnection`.
    pending_connects: Vec<oneshot::Sender<Result<TquicConnection, AsyncError>>>,
}

impl DriverHandler {
    fn new(incoming_tx: mpsc::Sender<TquicConnection>, is_server: bool) -> Self {
        Self {
            conns: HashMap::new(),
            incoming_tx,
            is_server,
            pending_connects: Vec::new(),
        }
    }

    /// Create per-connection channels and state, returning the handle.
    fn register_connection(&mut self, index: u64, remote_addr: SocketAddr) -> TquicConnection {
        let established = Arc::new(Notify::new());
        let (close_tx, close_rx) = watch::channel(None);
        let (conn_cmd_tx, conn_cmd_rx) = mpsc::channel(CONN_CMD_CAP);
        let (stream_cmd_tx, stream_cmd_rx) = mpsc::channel(STREAM_CMD_CAP);
        let (incoming_bi_tx, incoming_bi_rx) = mpsc::channel(INCOMING_STREAM_CAP);
        let (incoming_uni_tx, incoming_uni_rx) = mpsc::channel(INCOMING_STREAM_CAP);

        let state = ConnectionState {
            established: Arc::clone(&established),
            close_tx,
            stream_cmd_rx,
            conn_cmd_rx,
            stream_readables: HashMap::new(),
            stream_writables: HashMap::new(),
            incoming_bi_tx,
            incoming_uni_tx,
            stream_cmd_tx: stream_cmd_tx.clone(),
            remote_addr,
        };
        self.conns.insert(index, state);

        TquicConnection {
            index,
            cmd_tx: conn_cmd_tx,
            stream_cmd_tx,
            established,
            close_rx,
            incoming_bi_rx,
            incoming_uni_rx,
            remote_addr,
        }
    }

    /// Extract remote address from a connection's active path.
    fn remote_addr_of(conn: &Connection) -> SocketAddr {
        conn.paths_iter()
            .next()
            .map_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)), |ft| ft.remote)
    }
}

// ---------------------------------------------------------------------------
// HandlerShim - forwarding TransportHandler via Rc<RefCell<>>
// ---------------------------------------------------------------------------

/// Thin shim that forwards `TransportHandler` calls to the shared
/// `DriverHandler` behind `Rc<RefCell<>>`.
///
/// This lets the event loop and the `Endpoint` both access the same
/// `DriverHandler` state. Safe because the driver is single-threaded.
struct HandlerShim {
    inner: Rc<RefCell<DriverHandler>>,
}

impl TransportHandler for HandlerShim {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        self.inner.borrow_mut().on_conn_created(conn);
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        self.inner.borrow_mut().on_conn_established(conn);
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        self.inner.borrow_mut().on_conn_closed(conn);
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        self.inner.borrow_mut().on_stream_created(conn, stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        self.inner.borrow_mut().on_stream_readable(conn, stream_id);
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        self.inner.borrow_mut().on_stream_writable(conn, stream_id);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        self.inner.borrow_mut().on_stream_closed(conn, stream_id);
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {
        self.inner.borrow_mut().on_new_token(conn, token);
    }
}

// ---------------------------------------------------------------------------
// TransportHandler implementation for DriverHandler
// ---------------------------------------------------------------------------

impl TransportHandler for DriverHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let remote_addr = Self::remote_addr_of(conn);
        let handle = self.register_connection(index, remote_addr);

        if self.is_server {
            let _ = self.incoming_tx.try_send(handle);
        } else if let Some(tx) = self.pending_connects.pop() {
            let _ = tx.send(Ok(handle));
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        if let Some(state) = self.conns.get(&index) {
            state.established.notify_waiters();
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        let index = conn.index().unwrap_or(0);
        let info = build_close_info(conn);
        if let Some(state) = self.conns.remove(&index) {
            let _ = state.close_tx.send(Some(info));
        }
    }

    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {
        // Streams are created explicitly by the application; no-op.
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        if let Some(state) = self.conns.get(&index) {
            if let Some(notify) = state.stream_readables.get(&stream_id) {
                notify.notify_waiters();
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        if let Some(state) = self.conns.get(&index) {
            if let Some(notify) = state.stream_writables.get(&stream_id) {
                notify.notify_waiters();
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        let index = conn.index().unwrap_or(0);
        if let Some(state) = self.conns.get_mut(&index) {
            state.stream_readables.remove(&stream_id);
            state.stream_writables.remove(&stream_id);
        }
    }

    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {
        // Session ticket storage for 0-RTT; not yet implemented.
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
// Stream handle creation helpers
// ---------------------------------------------------------------------------

/// Create `SendStream` and `RecvStream` handles for a bidirectional stream.
fn make_bidi_handles(
    conn_index: u64,
    stream_id: u64,
    stream_cmd_tx: &mpsc::Sender<StreamCmd>,
    state: &mut ConnectionState,
) -> (SendStream, RecvStream) {
    let writable = Arc::new(Notify::new());
    let readable = Arc::new(Notify::new());
    state
        .stream_writables
        .insert(stream_id, Arc::clone(&writable));
    state
        .stream_readables
        .insert(stream_id, Arc::clone(&readable));

    // Pre-notify writable so the first write attempt does not block.
    writable.notify_one();

    let send = SendStream {
        stream_id,
        conn_index,
        cmd_tx: stream_cmd_tx.clone(),
        writable,
    };
    let recv = RecvStream {
        stream_id,
        conn_index,
        cmd_tx: stream_cmd_tx.clone(),
        readable,
    };
    (send, recv)
}

/// Create a `SendStream` handle for a locally-initiated unidirectional stream.
fn make_send_handle(
    conn_index: u64,
    stream_id: u64,
    stream_cmd_tx: &mpsc::Sender<StreamCmd>,
    state: &mut ConnectionState,
) -> SendStream {
    let writable = Arc::new(Notify::new());
    state
        .stream_writables
        .insert(stream_id, Arc::clone(&writable));
    writable.notify_one();
    SendStream {
        stream_id,
        conn_index,
        cmd_tx: stream_cmd_tx.clone(),
        writable,
    }
}

/// Create a `RecvStream` handle for a peer-initiated unidirectional stream.
#[allow(dead_code)]
fn make_recv_handle(
    conn_index: u64,
    stream_id: u64,
    stream_cmd_tx: &mpsc::Sender<StreamCmd>,
    state: &mut ConnectionState,
) -> RecvStream {
    let readable = Arc::new(Notify::new());
    state
        .stream_readables
        .insert(stream_id, Arc::clone(&readable));
    RecvStream {
        stream_id,
        conn_index,
        cmd_tx: stream_cmd_tx.clone(),
        readable,
    }
}

// ---------------------------------------------------------------------------
// Command processing
// ---------------------------------------------------------------------------

/// Process a single `EndpointCmd`.
///
/// Returns `true` if the loop should break (endpoint shutdown).
fn handle_endpoint_cmd(
    cmd: EndpointCmd,
    endpoint: &mut Endpoint,
    handler: &Rc<RefCell<DriverHandler>>,
    local_addr: SocketAddr,
) -> bool {
    match cmd {
        EndpointCmd::Connect {
            remote,
            server_name,
            session,
            token,
            result_tx,
        } => {
            handle_connect(
                endpoint,
                handler,
                local_addr,
                remote,
                &server_name,
                session,
                token,
                result_tx,
            );
            false
        }
        EndpointCmd::Close => true,
    }
}

/// Execute a `connect` command on the endpoint.
#[allow(clippy::too_many_arguments)]
fn handle_connect(
    endpoint: &mut Endpoint,
    handler: &Rc<RefCell<DriverHandler>>,
    local_addr: SocketAddr,
    remote: SocketAddr,
    server_name: &str,
    session: Option<Vec<u8>>,
    token: Option<Vec<u8>>,
    result_tx: oneshot::Sender<Result<TquicConnection, AsyncError>>,
) {
    handler.borrow_mut().pending_connects.push(result_tx);
    let res = endpoint.connect(
        local_addr,
        remote,
        Some(server_name),
        session.as_deref(),
        token.as_deref(),
        None,
    );
    if let Err(e) = res {
        if let Some(tx) = handler.borrow_mut().pending_connects.pop() {
            let _ = tx.send(Err(AsyncError::Tquic(e)));
        }
    }
}

/// Drain all pending `ConnCmd` and `StreamCmd` from every active connection.
fn drain_all_conn_commands(endpoint: &mut Endpoint, handler: &Rc<RefCell<DriverHandler>>) {
    let indices: Vec<u64> = handler.borrow().conns.keys().copied().collect();
    for index in indices {
        drain_conn_cmds(endpoint, handler, index);
        drain_stream_cmds(endpoint, handler, index);
    }
}

/// Drain pending connection-level commands for a single connection.
fn drain_conn_cmds(endpoint: &mut Endpoint, handler: &Rc<RefCell<DriverHandler>>, index: u64) {
    loop {
        let cmd = match try_recv_conn_cmd(handler, index) {
            Some(c) => c,
            None => return,
        };
        process_conn_cmd(endpoint, handler, index, cmd);
    }
}

/// Try to receive a single `ConnCmd` from the connection's channel.
fn try_recv_conn_cmd(handler: &Rc<RefCell<DriverHandler>>, index: u64) -> Option<ConnCmd> {
    let mut h = handler.borrow_mut();
    let state = h.conns.get_mut(&index)?;
    state.conn_cmd_rx.try_recv().ok()
}

/// Process a single connection-level command.
fn process_conn_cmd(
    endpoint: &mut Endpoint,
    handler: &Rc<RefCell<DriverHandler>>,
    index: u64,
    cmd: ConnCmd,
) {
    let conn = match endpoint.conn_get_mut(index) {
        Some(c) => c,
        None => return,
    };
    match cmd {
        ConnCmd::OpenBi { result_tx } => {
            let reply = open_bidi_stream(conn, handler, index);
            let _ = result_tx.send(reply);
        }
        ConnCmd::OpenUni { result_tx } => {
            let reply = open_uni_stream(conn, handler, index);
            let _ = result_tx.send(reply);
        }
        ConnCmd::SendDatagram { data, result_tx } => {
            let res = conn.dgram_send(data).map_err(AsyncError::Tquic);
            let _ = result_tx.send(res);
        }
        ConnCmd::RecvDatagram { result_tx } => {
            let res = conn.dgram_recv().map_err(AsyncError::Tquic);
            let _ = result_tx.send(res);
        }
        ConnCmd::Close { error_code, reason } => {
            let _ = conn.close(true, error_code, &reason);
        }
        ConnCmd::GetStats { result_tx } => {
            let owned = copy_connection_stats(conn);
            let _ = result_tx.send(owned);
        }
    }
}

/// Open a bidirectional stream and create the corresponding handles.
fn open_bidi_stream(
    conn: &mut Connection,
    handler: &Rc<RefCell<DriverHandler>>,
    index: u64,
) -> Result<(SendStream, RecvStream), AsyncError> {
    let stream_id = conn.stream_bidi_new(0, false).map_err(AsyncError::Tquic)?;
    let mut h = handler.borrow_mut();
    let state = h
        .conns
        .get_mut(&index)
        .ok_or(AsyncError::ConnectionClosed)?;
    let tx = state.stream_cmd_tx.clone();
    Ok(make_bidi_handles(index, stream_id, &tx, state))
}

/// Open a unidirectional stream and create the send handle.
fn open_uni_stream(
    conn: &mut Connection,
    handler: &Rc<RefCell<DriverHandler>>,
    index: u64,
) -> Result<SendStream, AsyncError> {
    let stream_id = conn.stream_uni_new(0, false).map_err(AsyncError::Tquic)?;
    let mut h = handler.borrow_mut();
    let state = h
        .conns
        .get_mut(&index)
        .ok_or(AsyncError::ConnectionClosed)?;
    let tx = state.stream_cmd_tx.clone();
    Ok(make_send_handle(index, stream_id, &tx, state))
}

/// Copy the essential fields of `ConnectionStats` into an owned value.
///
/// `ConnectionStats` does not implement `Clone`, so we copy manually.
fn copy_connection_stats(conn: &Connection) -> crate::connection::ConnectionStats {
    let s = conn.stats();
    crate::connection::ConnectionStats {
        recv_count: s.recv_count,
        recv_bytes: s.recv_bytes,
        sent_count: s.sent_count,
        sent_bytes: s.sent_bytes,
        lost_count: s.lost_count,
        lost_bytes: s.lost_bytes,
    }
}

/// Drain pending stream-level commands for a single connection.
fn drain_stream_cmds(endpoint: &mut Endpoint, handler: &Rc<RefCell<DriverHandler>>, index: u64) {
    loop {
        let cmd = match try_recv_stream_cmd(handler, index) {
            Some(c) => c,
            None => return,
        };
        process_stream_cmd(endpoint, index, cmd);
    }
}

/// Try to receive a single `StreamCmd` from the connection's channel.
fn try_recv_stream_cmd(handler: &Rc<RefCell<DriverHandler>>, index: u64) -> Option<StreamCmd> {
    let mut h = handler.borrow_mut();
    let state = h.conns.get_mut(&index)?;
    state.stream_cmd_rx.try_recv().ok()
}

/// Process a single stream-level command.
fn process_stream_cmd(endpoint: &mut Endpoint, index: u64, cmd: StreamCmd) {
    let conn = match endpoint.conn_get_mut(index) {
        Some(c) => c,
        None => return,
    };
    match cmd {
        StreamCmd::Write {
            stream_id,
            data,
            fin,
            result_tx,
        } => {
            let res = conn.stream_write(stream_id, data, fin);
            let _ = result_tx.send(res);
        }
        StreamCmd::Read {
            stream_id,
            buf_size,
            result_tx,
        } => {
            let mut buf = vec![0u8; buf_size];
            let res = conn.stream_read(stream_id, &mut buf).map(|(n, fin)| {
                buf.truncate(n);
                (buf, fin)
            });
            let _ = result_tx.send(res);
        }
        StreamCmd::Shutdown {
            stream_id,
            direction,
        } => {
            let _ = conn.stream_shutdown(stream_id, direction, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Driver event loop
// ---------------------------------------------------------------------------

/// The core select loop running on the `LocalSet`.
///
/// Receives UDP packets, processes endpoint/connection/stream commands,
/// handles timers, and calls `process_connections()` after every event.
async fn run_event_loop(
    socket: Rc<UdpSocket>,
    endpoint: &mut Endpoint,
    handler: &Rc<RefCell<DriverHandler>>,
    endpoint_cmd_rx: &mut mpsc::Receiver<EndpointCmd>,
    local_addr: SocketAddr,
) {
    let mut buf = vec![0u8; RECV_BUF_SIZE];

    loop {
        let timeout_dur = endpoint.timeout().unwrap_or(DEFAULT_IDLE_TIMEOUT);

        tokio::select! {
            // Branch 1: Incoming UDP packet.
            result = socket.recv_from(&mut buf) => {
                handle_udp_recv(result, &mut buf, endpoint, local_addr);
            }

            // Branch 2: Endpoint-level command.
            cmd = endpoint_cmd_rx.recv() => {
                match cmd {
                    Some(c) => {
                        if handle_endpoint_cmd(
                            c, endpoint, handler, local_addr,
                        ) {
                            break;
                        }
                    }
                    None => break,
                }
            }

            // Branch 3: Timer expiry.
            _ = tokio::time::sleep(timeout_dur) => {
                endpoint.on_timeout(Instant::now());
            }
        }

        // After any event: drain commands and process connections.
        drain_all_conn_commands(endpoint, handler);
        let _ = endpoint.process_connections();
    }
}

/// Handle the result of a UDP `recv_from` call.
fn handle_udp_recv(
    result: std::io::Result<(usize, SocketAddr)>,
    buf: &mut [u8],
    endpoint: &mut Endpoint,
    local_addr: SocketAddr,
) {
    match result {
        Ok((len, src)) => {
            let info = PacketInfo {
                src,
                dst: local_addr,
                time: Instant::now(),
            };
            let _ = endpoint.recv(&mut buf[..len], &info);
        }
        Err(e) => {
            warn!("UDP recv error: {e}");
        }
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Spawn the driver event loop and return a `Send`-safe endpoint handle.
///
/// The driver runs on a `LocalSet` in a dedicated thread because tquic
/// types are `!Send`. The returned `TquicEndpoint` communicates with
/// the driver via channels.
pub(crate) async fn spawn_driver(
    bind: SocketAddr,
    config: crate::Config,
    is_server: bool,
) -> Result<TquicEndpoint, AsyncError> {
    let std_socket = bind_udp_socket(bind)?;
    let local_addr = std_socket
        .local_addr()
        .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;

    let (endpoint_cmd_tx, endpoint_cmd_rx) = mpsc::channel::<EndpointCmd>(64);
    let (incoming_tx, incoming_rx) = mpsc::channel::<TquicConnection>(64);

    // Oneshot to synchronize: the driver thread signals readiness.
    let (ready_tx, ready_rx) = oneshot::channel::<Result<(), String>>();

    std::thread::Builder::new()
        .name("tquic-driver".into())
        .spawn(move || {
            run_driver_thread(
                std_socket,
                config,
                is_server,
                endpoint_cmd_rx,
                incoming_tx,
                local_addr,
                ready_tx,
            );
        })
        .map_err(|e| {
            AsyncError::Tquic(crate::Error::IoError(format!(
                "failed to spawn driver thread: {e}"
            )))
        })?;

    // Wait for the driver thread to signal readiness.
    ready_rx
        .await
        .map_err(|_| AsyncError::ChannelClosed)?
        .map_err(|e| AsyncError::Tquic(crate::Error::IoError(e)))?;

    Ok(TquicEndpoint::new(endpoint_cmd_tx, incoming_rx, local_addr))
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

// ---------------------------------------------------------------------------
// Driver thread
// ---------------------------------------------------------------------------

/// Entry point for the dedicated driver thread.
///
/// Sets up a single-threaded tokio runtime with a `LocalSet` and runs
/// the event loop inside it.
fn run_driver_thread(
    std_socket: std::net::UdpSocket,
    config: crate::Config,
    is_server: bool,
    mut endpoint_cmd_rx: mpsc::Receiver<EndpointCmd>,
    incoming_tx: mpsc::Sender<TquicConnection>,
    local_addr: SocketAddr,
    ready_tx: oneshot::Sender<Result<(), String>>,
) {
    let rt = match build_runtime() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    let local_set = tokio::task::LocalSet::new();
    local_set.block_on(&rt, async move {
        let tokio_socket = match UdpSocket::from_std(std_socket) {
            Ok(s) => Rc::new(s),
            Err(e) => {
                let _ = ready_tx.send(Err(format!("failed to convert socket: {e}")));
                return;
            }
        };

        let sender: Rc<dyn PacketSendHandler> = Rc::new(UdpSender {
            socket: Rc::clone(&tokio_socket),
        });

        let handler = Rc::new(RefCell::new(DriverHandler::new(incoming_tx, is_server)));

        let shim = HandlerShim {
            inner: Rc::clone(&handler),
        };

        let mut endpoint = Endpoint::new(Box::new(config), is_server, Box::new(shim), sender);

        // Signal readiness to the calling async task.
        let _ = ready_tx.send(Ok(()));

        run_event_loop(
            tokio_socket,
            &mut endpoint,
            &handler,
            &mut endpoint_cmd_rx,
            local_addr,
        )
        .await;
    });
}

/// Build a single-threaded tokio runtime for the driver.
fn build_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))
}
