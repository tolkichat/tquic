//! Thin-wrapper benchmark: sans-I/O tquic Endpoint on a dedicated thread
//! bridged to a benchmark harness via `std::sync::mpsc` channels.
//!
//! Compiled *without* the `tokio-runtime` feature so that tquic uses
//! `Rc<RefCell>` internally (zero-overhead single-threaded mode).
//! All tquic types (`Endpoint`, `Connection`, etc.) are `!Send` and
//! never leave their owning thread.

use std::cmp;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};

use tquic::{Config, Connection, Endpoint, PacketInfo, TlsConfig, TransportHandler};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum read buffer for stream I/O inside handlers.
const READ_BUF: usize = 2 * 1024 * 1024;

/// Poll timeout cap for the mio event loop.
///
/// The event loop uses `min(endpoint.timeout(), POLL_TIMEOUT)` so that
/// new commands in the queue are picked up within at most this interval.
const POLL_TIMEOUT: Duration = Duration::from_millis(1);

/// Maximum warm iterations per connection before refresh.
const WARM_CONN_LIFETIME: u64 = 50;

// ---------------------------------------------------------------------------
// Channel message types
// ---------------------------------------------------------------------------

/// Commands sent *into* the tquic client thread.
enum Cmd {
    /// Initiate a client connection to the given server address.
    Connect(SocketAddr),
    /// Open a bidi stream and write `payload` bytes, then FIN.
    SendData(Vec<u8>),
}

/// Events coming *out of* the tquic client thread.
enum Event {
    /// Connection established (handshake complete).
    Connected,
    /// Echoed data received (full payload).
    DataReceived(Vec<u8>),
}

// ---------------------------------------------------------------------------
// Thread-safe command queue
// ---------------------------------------------------------------------------

/// Thread-safe command queue shared between the benchmark harness and
/// the client's dedicated thread / handler.
struct SharedCmdQueue {
    inner: Mutex<VecDeque<Cmd>>,
}

impl SharedCmdQueue {
    fn new() -> Self {
        Self {
            inner: Mutex::new(VecDeque::new()),
        }
    }

    fn push(&self, cmd: Cmd) {
        self.inner.lock().unwrap().push_back(cmd);
    }

    fn pop(&self) -> Option<Cmd> {
        self.inner.lock().unwrap().pop_front()
    }
}

// ---------------------------------------------------------------------------
// TLS / Config helpers (same parameters as tokio_adapter benchmark)
// ---------------------------------------------------------------------------

/// Build a tquic `Config` for benchmarking.
fn make_config(is_server: bool) -> Config {
    let mut conf = Config::new().expect("Config::new failed");
    configure_quic_params(&mut conf);
    configure_tls(&mut conf, is_server);
    conf
}

/// Set QUIC transport parameters for high throughput.
fn configure_quic_params(conf: &mut Config) {
    conf.set_max_idle_timeout(30_000);
    conf.set_recv_udp_payload_size(1350);
    conf.set_max_connection_window(1024 * 1024 * 1024);
    conf.set_max_stream_window(64 * 1024 * 1024);
    conf.set_initial_max_data(1024 * 1024 * 1024);
    conf.set_initial_max_stream_data_bidi_local(64 * 1024 * 1024);
    conf.set_initial_max_stream_data_bidi_remote(64 * 1024 * 1024);
    conf.set_initial_max_stream_data_uni(1_000_000);
    conf.set_initial_max_streams_bidi(100_000);
    conf.set_initial_max_streams_uni(100);
    conf.set_max_datagram_frame_size(65535);
}

/// Configure TLS for client or server role.
fn configure_tls(conf: &mut Config, is_server: bool) {
    let alpn = vec![b"bench".to_vec()];
    let tls_config = if is_server {
        TlsConfig::new_server_config(
            "src/tls/testdata/cert.crt",
            "src/tls/testdata/cert.key",
            alpn,
            false,
        )
        .expect("server TLS config")
    } else {
        TlsConfig::new_client_config(alpn, false).expect("client TLS config")
    };
    conf.set_tls_config(tls_config);
}

/// Format a byte size as a human-readable label.
fn format_size(bytes: usize) -> String {
    match bytes {
        n if n >= 1024 * 1024 => format!("{}MB", n / (1024 * 1024)),
        n if n >= 1024 => format!("{}KB", n / 1024),
        n => format!("{}B", n),
    }
}

// ---------------------------------------------------------------------------
// Socket wrapper implementing PacketSendHandler
// ---------------------------------------------------------------------------

/// A simple UDP socket wrapper that implements `PacketSendHandler`.
///
/// Without `tokio-runtime`, `PacketSendHandler` does NOT require
/// `Send + Sync`, so we can wrap a plain `mio::net::UdpSocket`.
struct BenchSocket {
    socket: mio::net::UdpSocket,
}

impl BenchSocket {
    fn new(registry: &mio::Registry) -> Self {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut socket = mio::net::UdpSocket::bind(addr).unwrap();
        let token = mio::Token(0);
        registry
            .register(&mut socket, token, mio::Interest::READABLE)
            .unwrap();
        Self { socket }
    }

    fn local_addr(&self) -> SocketAddr {
        self.socket.local_addr().unwrap()
    }
}

impl tquic::PacketSendHandler for BenchSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> tquic::Result<usize> {
        let mut count = 0;
        for (pkt, info) in pkts {
            match self.socket.send_to(pkt, info.dst) {
                Ok(_) => count += 1,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => {
                    return Err(tquic::Error::InvalidOperation(format!("send_to: {e:?}")));
                }
            }
        }
        Ok(count)
    }
}

/// `Rc` alias for sharing the socket with the Endpoint.
///
/// Without `tokio-runtime`, tquic expects `Rc<dyn PacketSendHandler>`.
type SocketRc = std::rc::Rc<BenchSocket>;

// ---------------------------------------------------------------------------
// Client handler: bridges stream data via shared command queue + mpsc events
// ---------------------------------------------------------------------------

/// Shared pending-write state between the event loop and handler.
///
/// When a `stream_write` doesn't consume the entire payload (flow control),
/// the remainder is stored here. The handler's `on_stream_writable` callback
/// drains it.
struct PendingWrite {
    stream_id: u64,
    data: Vec<u8>,
    offset: usize,
}

/// Client-side `TransportHandler` that reads echoed data, sends events,
/// and drains any pending writes when flow control opens up.
struct BridgeHandler {
    event_tx: mpsc::Sender<Event>,
    recv_buf: Vec<u8>,
    pending: Arc<Mutex<Option<PendingWrite>>>,
    established: Arc<AtomicBool>,
}

impl BridgeHandler {
    fn new(
        event_tx: mpsc::Sender<Event>,
        pending: Arc<Mutex<Option<PendingWrite>>>,
        established: Arc<AtomicBool>,
    ) -> Self {
        Self {
            event_tx,
            recv_buf: Vec::new(),
            pending,
            established,
        }
    }

    /// Flush any pending write data when the stream becomes writable.
    fn flush_pending(&self, conn: &mut Connection) {
        let mut guard = self.pending.lock().unwrap();
        let pw = match guard.as_mut() {
            Some(pw) => pw,
            None => return,
        };
        let remaining = &pw.data[pw.offset..];
        if remaining.is_empty() {
            *guard = None;
            return;
        }
        let buf = bytes::Bytes::copy_from_slice(remaining);
        if let Ok(n) = conn.stream_write(pw.stream_id, buf, true) {
            pw.offset += n;
            if pw.offset >= pw.data.len() {
                *guard = None;
            }
        }
    }
}

impl TransportHandler for BridgeHandler {
    fn on_conn_created(&mut self, _conn: &mut Connection) {}

    fn on_conn_established(&mut self, _conn: &mut Connection) {
        self.established.store(true, Ordering::Relaxed);
        let _ = self.event_tx.send(Event::Connected);
    }

    fn on_conn_closed(&mut self, _conn: &mut Connection) {}
    fn on_stream_created(&mut self, _conn: &mut Connection, _stream_id: u64) {}

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut buf = vec![0u8; READ_BUF];
        loop {
            match conn.stream_read(stream_id, &mut buf) {
                Ok((n, fin)) => {
                    self.recv_buf.extend_from_slice(&buf[..n]);
                    if fin {
                        let data = std::mem::take(&mut self.recv_buf);
                        let _ = self.event_tx.send(Event::DataReceived(data));
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, _stream_id: u64) {
        self.flush_pending(conn);
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

// ---------------------------------------------------------------------------
// Server handler: echo server
// ---------------------------------------------------------------------------

/// Per-stream context for the echo server.
struct EchoStreamCtx {
    buf: bytes::BytesMut,
    fin: bool,
}

/// Server-side `TransportHandler` that echoes received data back.
struct EchoHandler;

impl TransportHandler for EchoHandler {
    fn on_conn_created(&mut self, _conn: &mut Connection) {}
    fn on_conn_established(&mut self, _conn: &mut Connection) {}
    fn on_conn_closed(&mut self, _conn: &mut Connection) {}

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let ctx = EchoStreamCtx {
            buf: bytes::BytesMut::new(),
            fin: false,
        };
        conn.stream_set_context(stream_id, ctx).unwrap();
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut buf = vec![0u8; READ_BUF];
        while let Ok((len, fin)) = conn.stream_read(stream_id, &mut buf) {
            let ctx = conn.stream_context(stream_id).unwrap();
            let ctx = ctx.downcast_mut::<EchoStreamCtx>().unwrap();
            ctx.buf.extend_from_slice(&buf[..len]);
            if fin {
                ctx.fin = true;
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let cap = conn.stream_capacity(stream_id).unwrap();
        let ctx = conn.stream_context(stream_id).unwrap();
        let ctx = ctx.downcast_mut::<EchoStreamCtx>().unwrap();
        if ctx.buf.is_empty() {
            return;
        }
        let len = cmp::min(cap, ctx.buf.len());
        let buf = ctx.buf.split_to(len).freeze();
        let fin = ctx.fin && ctx.buf.is_empty();
        conn.stream_write(stream_id, buf, fin).unwrap();
    }

    fn on_stream_closed(&mut self, _conn: &mut Connection, _stream_id: u64) {}
    fn on_new_token(&mut self, _conn: &mut Connection, _token: Vec<u8>) {}
}

// ---------------------------------------------------------------------------
// mio event loop helpers (run on the dedicated threads)
// ---------------------------------------------------------------------------

/// Read incoming UDP packets and feed them to the endpoint.
fn process_read_event(endpoint: &mut Endpoint, sock: &BenchSocket) {
    let mut recv_buf = vec![0u8; 65535];
    loop {
        let (len, remote) = match sock.socket.recv_from(&mut recv_buf) {
            Ok(v) => v,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("socket recv error: {e:?}"),
        };
        let pkt_buf = &mut recv_buf[..len];
        let pkt_info = PacketInfo {
            src: remote,
            dst: sock.socket.local_addr().unwrap(),
            time: Instant::now(),
        };
        let _ = endpoint.recv(pkt_buf, &pkt_info);
    }
}

/// Run one mio poll + process cycle. Returns `true` to stop.
fn event_loop_tick(
    endpoint: &mut Endpoint,
    poll: &mut mio::Poll,
    events: &mut mio::Events,
    sock: &BenchSocket,
    stop: &AtomicBool,
) -> bool {
    if stop.load(Ordering::Relaxed) {
        return true;
    }
    // Cap poll timeout at POLL_TIMEOUT so the client event loop wakes
    // frequently enough to drain new commands from the shared queue.
    let timeout = endpoint
        .timeout()
        .map(|t| cmp::min(t, POLL_TIMEOUT))
        .or(Some(POLL_TIMEOUT));
    poll.poll(events, timeout).unwrap();

    if events.is_empty() {
        endpoint.on_timeout(Instant::now());
    } else {
        for event in events.iter() {
            if event.is_readable() {
                process_read_event(endpoint, sock);
            }
        }
    }
    let _ = endpoint.process_connections();
    false
}

/// Run the mio event loop until `stop` is set.
fn run_event_loop(
    endpoint: &mut Endpoint,
    poll: &mut mio::Poll,
    sock: &BenchSocket,
    stop: &AtomicBool,
) {
    let mut events = mio::Events::with_capacity(1024);
    while !event_loop_tick(endpoint, poll, &mut events, sock, stop) {}
}

// ---------------------------------------------------------------------------
// Server thread
// ---------------------------------------------------------------------------

/// Spawn a server thread that runs an echo endpoint until `stop` is set.
///
/// Returns the server's listen address and the join handle.
fn spawn_server(stop: Arc<AtomicBool>) -> (SocketAddr, thread::JoinHandle<()>) {
    let (addr_tx, addr_rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let mut poll = mio::Poll::new().unwrap();
        let sock = BenchSocket::new(poll.registry());
        addr_tx.send(sock.local_addr()).unwrap();

        let sock_rc = SocketRc::new(sock);
        let config = make_config(true);
        let handler = Box::new(EchoHandler);
        let mut endpoint = Endpoint::new(Box::new(config), true, handler, sock_rc.clone());

        run_event_loop(&mut endpoint, &mut poll, &sock_rc, &stop);
    });

    let addr = addr_rx.recv().unwrap();
    (addr, handle)
}

// ---------------------------------------------------------------------------
// Client thread
// ---------------------------------------------------------------------------

/// Shared state passed from the benchmark harness into the client thread.
struct ClientShared {
    cmd_queue: Arc<SharedCmdQueue>,
    pending: Arc<Mutex<Option<PendingWrite>>>,
    established: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

/// Client event loop: checks for commands on each tick, then polls mio.
///
/// Uses `endpoint.conn_get_mut()` to write data to the connection
/// directly from the event loop, bypassing the handler for writes.
fn run_client_loop(
    endpoint: &mut Endpoint,
    poll: &mut mio::Poll,
    sock: &SocketRc,
    local_addr: SocketAddr,
    shared: &ClientShared,
) {
    let mut events = mio::Events::with_capacity(1024);
    let mut conn_index: Option<u64> = None;
    let mut next_stream_id: u64 = 0;

    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        drain_client_commands(
            endpoint,
            &shared.cmd_queue,
            local_addr,
            &mut conn_index,
            &mut next_stream_id,
            &shared.pending,
            &shared.established,
        );

        if event_loop_tick(endpoint, poll, &mut events, sock, &shared.stop) {
            break;
        }
    }
}

/// Process pending commands from the shared queue.
///
/// Connect: creates a new connection via the endpoint.
/// SendData: writes payload to a new bidi stream. If the connection
/// is not yet established, the command is pushed back for the next tick.
fn drain_client_commands(
    endpoint: &mut Endpoint,
    cmd_queue: &SharedCmdQueue,
    local_addr: SocketAddr,
    conn_index: &mut Option<u64>,
    next_stream_id: &mut u64,
    pending: &Arc<Mutex<Option<PendingWrite>>>,
    established: &Arc<AtomicBool>,
) {
    while let Some(cmd) = cmd_queue.pop() {
        match cmd {
            Cmd::Connect(server_addr) => {
                let idx = endpoint
                    .connect(local_addr, server_addr, Some("localhost"), None, None, None)
                    .unwrap();
                *conn_index = Some(idx);
                *next_stream_id = 0;
                let _ = endpoint.process_connections();
            }
            Cmd::SendData(payload) => {
                if !established.load(Ordering::Relaxed) {
                    // Handshake not done yet; push back for next tick.
                    cmd_queue.push(Cmd::SendData(payload));
                    return;
                }
                if let Some(idx) = *conn_index {
                    write_to_stream(endpoint, idx, next_stream_id, &payload, pending);
                }
            }
        }
    }
}

/// Write a payload to a new bidi stream on the connection.
///
/// If flow control prevents writing the full payload, the remainder
/// is stored in `pending` for the handler's `on_stream_writable` to drain.
fn write_to_stream(
    endpoint: &mut Endpoint,
    conn_index: u64,
    next_stream_id: &mut u64,
    payload: &[u8],
    pending: &Arc<Mutex<Option<PendingWrite>>>,
) {
    let conn = endpoint
        .conn_get_mut(conn_index)
        .expect("connection must exist");
    let stream_id = *next_stream_id;
    *next_stream_id += 4; // client-initiated bidi: 0, 4, 8, ...
    let buf = bytes::Bytes::copy_from_slice(payload);
    match conn.stream_write(stream_id, buf, true) {
        Ok(written) => {
            if written < payload.len() {
                *pending.lock().unwrap() = Some(PendingWrite {
                    stream_id,
                    data: payload.to_vec(),
                    offset: written,
                });
            }
        }
        Err(tquic::Error::Done) => {
            // Stream capacity is zero; store entire payload as pending.
            *pending.lock().unwrap() = Some(PendingWrite {
                stream_id,
                data: payload.to_vec(),
                offset: 0,
            });
        }
        Err(e) => panic!("stream_write failed: {e:?}"),
    }
}

/// Spawn a client thread with the bridge handler.
///
/// Returns `(cmd_queue, event_rx, local_addr, join_handle)`.
fn spawn_client(
    stop: Arc<AtomicBool>,
) -> (
    Arc<SharedCmdQueue>,
    mpsc::Receiver<Event>,
    SocketAddr,
    thread::JoinHandle<()>,
) {
    let cmd_queue = Arc::new(SharedCmdQueue::new());
    let cmd_queue_inner = Arc::clone(&cmd_queue);
    let (event_tx, event_rx) = mpsc::channel();
    let (addr_tx, addr_rx) = mpsc::channel();

    let handle = thread::spawn(move || {
        let mut poll = mio::Poll::new().unwrap();
        let sock = BenchSocket::new(poll.registry());
        let local_addr = sock.local_addr();
        addr_tx.send(local_addr).unwrap();

        let pending: Arc<Mutex<Option<PendingWrite>>> = Arc::new(Mutex::new(None));
        let established = Arc::new(AtomicBool::new(false));
        let sock_rc = SocketRc::new(sock);
        let config = make_config(false);
        let handler = Box::new(BridgeHandler::new(
            event_tx,
            Arc::clone(&pending),
            Arc::clone(&established),
        ));
        let mut endpoint = Endpoint::new(Box::new(config), false, handler, sock_rc.clone());

        let shared = ClientShared {
            cmd_queue: cmd_queue_inner,
            pending,
            established,
            stop,
        };
        run_client_loop(&mut endpoint, &mut poll, &sock_rc, local_addr, &shared);
    });

    let local_addr = addr_rx.recv().unwrap();
    (cmd_queue, event_rx, local_addr, handle)
}

// ---------------------------------------------------------------------------
// Event helpers (called from the benchmark harness on the main thread)
// ---------------------------------------------------------------------------

/// Wait for a `Connected` event with timeout.
fn wait_connected(event_rx: &mpsc::Receiver<Event>, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match event_rx.recv_timeout(remaining) {
            Ok(Event::Connected) => return,
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("handshake timed out"),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("client thread died"),
        }
    }
}

/// Wait for `DataReceived` event with timeout.
fn wait_data(event_rx: &mpsc::Receiver<Event>, timeout: Duration) -> Vec<u8> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match event_rx.recv_timeout(remaining) {
            Ok(Event::DataReceived(data)) => return data,
            Ok(_) => continue,
            Err(mpsc::RecvTimeoutError::Timeout) => panic!("data receive timed out"),
            Err(mpsc::RecvTimeoutError::Disconnected) => panic!("client thread died"),
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark pair
// ---------------------------------------------------------------------------

/// Manages a client/server pair on dedicated threads for benchmarking.
struct BenchPair {
    stop: Arc<AtomicBool>,
    #[allow(dead_code)]
    server_addr: SocketAddr,
    server_handle: Option<thread::JoinHandle<()>>,
    cmd_queue: Arc<SharedCmdQueue>,
    event_rx: mpsc::Receiver<Event>,
    #[allow(dead_code)]
    client_addr: SocketAddr,
    client_handle: Option<thread::JoinHandle<()>>,
}

impl BenchPair {
    /// Create a new client/server pair, each on its own thread.
    fn new() -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let (server_addr, server_handle) = spawn_server(Arc::clone(&stop));
        let (cmd_queue, event_rx, client_addr, client_handle) = spawn_client(Arc::clone(&stop));

        Self {
            stop,
            server_addr,
            server_handle: Some(server_handle),
            cmd_queue,
            event_rx,
            client_addr,
            client_handle: Some(client_handle),
        }
    }

    /// Tell the client to connect to the server.
    fn connect(&self) {
        self.cmd_queue.push(Cmd::Connect(self.server_addr));
    }

    /// Wait for the handshake to complete.
    fn wait_connected(&self) {
        wait_connected(&self.event_rx, Duration::from_secs(5));
    }

    /// Queue data to be sent once connected, then wait for echo.
    fn send_data(&self, payload: &[u8]) {
        self.cmd_queue.push(Cmd::SendData(payload.to_vec()));
    }

    /// Wait for the echo response.
    fn wait_echo(&self) -> Vec<u8> {
        wait_data(&self.event_rx, Duration::from_secs(30))
    }
}

impl Drop for BenchPair {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.server_handle.take() {
            let _ = h.join();
        }
        if let Some(h) = self.client_handle.take() {
            let _ = h.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Benchmark group 1: Cold (fresh connection per iteration)
// ---------------------------------------------------------------------------

/// Measure cold stream throughput: fresh connection + echo roundtrip.
fn bench_thin_wrapper_cold(c: &mut Criterion) {
    let mut group = c.benchmark_group("thin_wrapper_cold");
    group.sampling_mode(SamplingMode::Flat);

    for &size in &[1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(size)),
            &size,
            |b, &payload_size| {
                let payload = vec![0xABu8; payload_size];
                b.iter(|| {
                    let pair = BenchPair::new();
                    pair.connect();
                    pair.wait_connected();
                    pair.send_data(&payload);
                    let received = pair.wait_echo();
                    assert_eq!(received.len(), payload_size, "echo size mismatch");
                    std::hint::black_box(&received);
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 2: Warm (reuse connection, measure stream I/O only)
// ---------------------------------------------------------------------------

/// Measure warm stream throughput with `iter_custom`.
///
/// The connection is established once; only stream open/write/echo/read
/// is timed. Connection is refreshed every [`WARM_CONN_LIFETIME`] iters.
fn bench_thin_wrapper_warm(c: &mut Criterion) {
    let mut group = c.benchmark_group("thin_wrapper_warm");
    group.sampling_mode(SamplingMode::Flat);

    for &size in &[1024usize, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(size)),
            &size,
            |b, &payload_size| {
                b.iter_custom(|iters| warm_measurement(iters, payload_size));
            },
        );
    }

    group.finish();
}

/// Run `iters` warm echo iterations, timing only the stream I/O.
///
/// Refreshes the connection pair every [`WARM_CONN_LIFETIME`] iterations
/// and excludes reconnection time from the measurement.
fn warm_measurement(iters: u64, payload_size: usize) -> Duration {
    let payload = vec![0xABu8; payload_size];
    let mut total = Duration::ZERO;
    let mut done: u64 = 0;
    let mut conn_iter: u64 = 0;

    let mut pair = new_connected_pair();

    while done < iters {
        if conn_iter >= WARM_CONN_LIFETIME {
            drop(pair);
            pair = new_connected_pair();
            conn_iter = 0;
        }

        pair.send_data(&payload);
        let start = Instant::now();
        let received = pair.wait_echo();
        total += start.elapsed();

        assert_eq!(received.len(), payload_size, "echo size mismatch");
        std::hint::black_box(&received);
        done += 1;
        conn_iter += 1;
    }

    total
}

/// Create a connected pair (handshake already complete, untimed).
fn new_connected_pair() -> BenchPair {
    let pair = BenchPair::new();
    pair.connect();
    pair.wait_connected();
    pair
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group! {
    name = cold;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(15))
        .warm_up_time(Duration::from_secs(3));
    targets = bench_thin_wrapper_cold
}

criterion_group! {
    name = warm;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(1));
    targets = bench_thin_wrapper_warm
}

criterion_main!(cold, warm);
