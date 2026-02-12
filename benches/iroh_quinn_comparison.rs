//! iroh-quinn comparison benchmarks for side-by-side tquic performance analysis.
//!
//! Measures the same scenarios as `quinn_comparison.rs` plus warm-connection
//! throughput from `tokio_adapter.rs`:
//!   1. Handshake latency (connect + established)
//!   2. Bidirectional stream throughput (cold: 1 KB, 64 KB, 1 MB)
//!   3. Datagram throughput (10, 100, 1000 x 1200 B)
//!   4. Warm stream throughput (pre-established connection: 1 KB, 64 KB, 1 MB)
//!
//! iroh-quinn is n0-computer's Quinn fork with multipath QUIC support.
//!
//! Run all three benchmarks for comparison:
//! ```bash
//! cargo bench -p tquic --features tokio-reactor --bench tokio_adapter
//! cargo bench -p tquic --bench quinn_comparison
//! cargo bench -p tquic --bench iroh_quinn_comparison
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use iroh_quinn::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use iroh_quinn::{
    ClientConfig, Connection, Endpoint, RecvStream, SendStream, ServerConfig, TransportConfig,
    VarInt,
};
use rcgen::CertifiedKey;

// ---------------------------------------------------------------------------
// Constants (same as quinn_comparison.rs / tokio_adapter.rs)
// ---------------------------------------------------------------------------

/// Maximum datagram payload (matches tquic benchmark).
const DATAGRAM_PAYLOAD_SIZE: usize = 1200;

/// Maximum time to wait for datagram drain on localhost.
const DGRAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum stream iterations per connection before proactive refresh.
const WARM_CONN_LIFETIME: u64 = 50;

// ---------------------------------------------------------------------------
// TLS / Config helpers
// ---------------------------------------------------------------------------

/// A reusable self-signed certificate for benchmarks.
struct BenchCert {
    cert_der: CertificateDer<'static>,
    key_der: PrivatePkcs8KeyDer<'static>,
}

/// Generate a self-signed certificate for localhost.
fn generate_bench_cert() -> BenchCert {
    let CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("self-signed cert generation");
    BenchCert {
        cert_der: cert.der().clone(),
        key_der: PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    }
}

/// Build a `TransportConfig` matching quinn_comparison.rs parameters.
fn bench_transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("valid idle timeout"),
        ))
        .max_concurrent_bidi_streams(VarInt::from_u32(100))
        .max_concurrent_uni_streams(VarInt::from_u32(100))
        .stream_receive_window(VarInt::from_u32(1_000_000))
        .receive_window(VarInt::from_u32(10_000_000))
        .datagram_receive_buffer_size(Some(65535))
        .send_window(10_000_000);
    transport
}

/// Build a `TransportConfig` with generous windows for warm benchmarks.
///
/// Warm benchmarks reuse connections across many stream iterations,
/// requiring larger flow-control windows to avoid stalling.
fn warm_transport_config() -> TransportConfig {
    let mut transport = TransportConfig::default();
    transport
        .max_idle_timeout(Some(
            Duration::from_secs(30)
                .try_into()
                .expect("valid idle timeout"),
        ))
        .max_concurrent_bidi_streams(VarInt::from_u32(100_000))
        .max_concurrent_uni_streams(VarInt::from_u32(100))
        .stream_receive_window(VarInt::from_u32(64_000_000))
        .receive_window(VarInt::try_from(1_000_000_000u64).expect("valid window"))
        .datagram_receive_buffer_size(Some(65535))
        .send_window(64_000_000);
    transport
}

/// Build a `ServerConfig` with warm-benchmark flow-control windows.
fn make_warm_server_config(cert: &BenchCert) -> ServerConfig {
    let mut config = ServerConfig::with_single_cert(
        vec![cert.cert_der.clone()],
        cert.key_der.clone_key().into(),
    )
    .expect("server config from self-signed cert");
    config.transport_config(Arc::new(warm_transport_config()));
    config
}

/// Build a `ClientConfig` with warm-benchmark flow-control windows.
fn make_warm_client_config(cert: &BenchCert) -> ClientConfig {
    let mut roots = iroh_quinn::rustls::RootCertStore::empty();
    roots
        .add(cert.cert_der.clone())
        .expect("add self-signed root");
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots))
        .expect("client config with root certs");
    config.transport_config(Arc::new(warm_transport_config()));
    config
}

/// Build a `ServerConfig` with self-signed cert.
fn make_server_config(cert: &BenchCert) -> ServerConfig {
    let mut config = ServerConfig::with_single_cert(
        vec![cert.cert_der.clone()],
        cert.key_der.clone_key().into(),
    )
    .expect("server config from self-signed cert");
    config.transport_config(Arc::new(bench_transport_config()));
    config
}

/// Build a `ClientConfig` trusting the bench cert.
fn make_client_config(cert: &BenchCert) -> ClientConfig {
    let mut roots = iroh_quinn::rustls::RootCertStore::empty();
    roots
        .add(cert.cert_der.clone())
        .expect("add self-signed root");
    let mut config = ClientConfig::with_root_certificates(Arc::new(roots))
        .expect("client config with root certs");
    config.transport_config(Arc::new(bench_transport_config()));
    config
}

/// Localhost address with OS-assigned port.
fn localhost_any() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

// ---------------------------------------------------------------------------
// Connection setup helpers
// ---------------------------------------------------------------------------

/// Start an iroh-quinn server endpoint from a pre-built config.
fn start_server(config: ServerConfig) -> (Endpoint, SocketAddr) {
    let endpoint =
        Endpoint::server(config, localhost_any()).expect("iroh-quinn server endpoint creation");
    let addr = endpoint.local_addr().expect("server local addr");
    (endpoint, addr)
}

/// Start an iroh-quinn client endpoint from a pre-built config.
fn start_client(config: ClientConfig) -> Endpoint {
    let endpoint = Endpoint::client(localhost_any()).expect("iroh-quinn client endpoint creation");
    endpoint.set_default_client_config(config);
    endpoint
}

/// Establish a client-server connection pair with completed handshake.
///
/// Spawns the server accept on a background task so both endpoints'
/// I/O can progress concurrently.
async fn establish_pair(
    server: &Endpoint,
    client: &Endpoint,
    server_addr: SocketAddr,
) -> (Connection, Connection) {
    let server_handle = server.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = server_handle
            .accept()
            .await
            .expect("server incoming connection");
        incoming
            .accept()
            .expect("incoming accept")
            .await
            .expect("server connection established")
    });
    let client_conn = client
        .connect(server_addr, "localhost")
        .expect("client connect initiation")
        .await
        .expect("client connection established");
    let server_conn = accept_task.await.expect("accept task join");
    (client_conn, server_conn)
}

// ---------------------------------------------------------------------------
// Stream I/O helpers
// ---------------------------------------------------------------------------

/// Write all data and signal FIN on an iroh-quinn send stream.
async fn write_and_finish(send: &mut SendStream, data: &[u8]) {
    send.write_all(data).await.expect("stream write_all");
    send.finish().expect("stream finish");
}

/// Read all data from an iroh-quinn recv stream until FIN.
async fn read_to_end(recv: &mut RecvStream, size_limit: usize) -> Vec<u8> {
    recv.read_to_end(size_limit)
        .await
        .expect("stream read_to_end")
}

// ---------------------------------------------------------------------------
// Echo server helpers
// ---------------------------------------------------------------------------

/// Run an echo server that accepts one bidi stream and echoes data back.
///
/// Returns the connection to keep it alive until the caller joins the task.
async fn echo_one_stream(server_conn: Connection) -> Connection {
    let (mut srv_send, mut srv_recv) = server_conn
        .accept_bi()
        .await
        .expect("server accept_bi for echo");
    let data = read_to_end(&mut srv_recv, 2_000_000).await;
    write_and_finish(&mut srv_send, &data).await;
    server_conn
}

/// Run a datagram sink that reads `count` datagrams from a connection.
///
/// Tolerates connection closure (datagrams are unreliable).
/// Returns the number of datagrams successfully received.
async fn drain_datagrams(conn: &Connection, count: usize) -> usize {
    let mut received = 0;
    for _ in 0..count {
        match conn.read_datagram().await {
            Ok(_) => received += 1,
            Err(_) => break,
        }
    }
    received
}

// ---------------------------------------------------------------------------
// Runtime helper
// ---------------------------------------------------------------------------

/// Create a new tokio runtime for benchmarks.
fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime creation")
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
// Benchmark group 1: Handshake
// ---------------------------------------------------------------------------

/// Measure the time to establish a QUIC connection (connect + handshake).
///
/// TLS configs are pre-built outside the iteration loop so that
/// certificate generation cost is not measured.
fn bench_iroh_quinn_handshake(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);

    c.bench_function("iroh_quinn_handshake", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (server, server_addr) = start_server(server_config.clone());
                let client = start_client(client_config.clone());
                let (client_conn, _server_conn) =
                    establish_pair(&server, &client, server_addr).await;
                std::hint::black_box(&client_conn);
                client_conn.close(0u32.into(), b"done");
            });
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark group 2: Stream throughput (cold)
// ---------------------------------------------------------------------------

/// Measure bidirectional stream throughput at various payload sizes.
///
/// Each iteration creates a fresh connection (cold handshake included).
fn bench_iroh_quinn_stream_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);
    let mut group = c.benchmark_group("iroh_quinn_stream_throughput");
    group.sampling_mode(SamplingMode::Flat);

    for &size in &[1024, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        let sc = server_config.clone();
        let cc = client_config.clone();
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(size)),
            &size,
            |b, &payload_size| {
                b.iter(|| {
                    rt.block_on(run_stream_iter(sc.clone(), cc.clone(), payload_size));
                });
            },
        );
    }

    group.finish();
}

/// Run a single cold stream throughput iteration.
///
/// Creates a connection pair, spawns an echo server,
/// writes `payload_size` bytes and reads the echo back.
async fn run_stream_iter(
    server_config: ServerConfig,
    client_config: ClientConfig,
    payload_size: usize,
) {
    let (server, server_addr) = start_server(server_config);
    let client = start_client(client_config);
    let (client_conn, server_conn) = establish_pair(&server, &client, server_addr).await;

    let echo_task = tokio::spawn(echo_one_stream(server_conn));

    let payload = vec![0xABu8; payload_size];
    let (mut client_send, mut client_recv) = client_conn.open_bi().await.expect("open_bi");
    write_and_finish(&mut client_send, &payload).await;
    let received = read_to_end(&mut client_recv, payload_size + 1).await;

    std::hint::black_box(&received);
    assert_eq!(received.len(), payload_size, "echo size mismatch");

    client_conn.close(0u32.into(), b"done");
    let _ = echo_task.await;
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Datagram throughput
// ---------------------------------------------------------------------------

/// Measure datagram send throughput at various batch sizes.
fn bench_iroh_quinn_datagram_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);
    let mut group = c.benchmark_group("iroh_quinn_datagram_throughput");
    group.sampling_mode(SamplingMode::Flat);

    for &count in &[10u64, 100, 1000] {
        group.throughput(Throughput::Elements(count));
        let sc = server_config.clone();
        let cc = client_config.clone();
        group.bench_with_input(
            BenchmarkId::from_parameter(count),
            &count,
            |b, &dgram_count| {
                b.iter(|| {
                    rt.block_on(run_datagram_iter(
                        sc.clone(),
                        cc.clone(),
                        dgram_count as usize,
                    ));
                });
            },
        );
    }

    group.finish();
}

/// Run a single datagram throughput iteration.
///
/// Creates a connection pair, sends `count` datagrams from client,
/// and drains them on the server side.
async fn run_datagram_iter(server_config: ServerConfig, client_config: ClientConfig, count: usize) {
    let (server, server_addr) = start_server(server_config);
    let client = start_client(client_config);
    let (client_conn, server_conn) = establish_pair(&server, &client, server_addr).await;

    let drain_task = tokio::spawn(async move { drain_datagrams(&server_conn, count).await });

    let dgram_payload = Bytes::from(vec![0xCDu8; DATAGRAM_PAYLOAD_SIZE]);
    send_datagrams(&client_conn, &dgram_payload, count);

    // Brief yield to let the driver flush remaining packets on localhost.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Best-effort wait: datagrams are unreliable, so don't panic on timeout.
    let received = tokio::time::timeout(DGRAM_DRAIN_TIMEOUT, drain_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    std::hint::black_box(received);
    client_conn.close(0u32.into(), b"done");
}

/// Send `count` datagrams synchronously (iroh-quinn's send_datagram is sync).
fn send_datagrams(conn: &Connection, payload: &Bytes, count: usize) {
    for _ in 0..count {
        let _ = conn.send_datagram(payload.clone());
    }
}

// ---------------------------------------------------------------------------
// Benchmark group 4: Stream throughput (warm connection)
// ---------------------------------------------------------------------------

/// Measure stream throughput with a pre-established connection.
///
/// Unlike [`bench_iroh_quinn_stream_throughput`], the QUIC handshake happens
/// once *before* the benchmark loop. Each iteration only measures:
/// `open_bi -> write -> server echo -> read`.
fn bench_iroh_quinn_stream_throughput_warm(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_warm_server_config(&cert);
    let client_config = make_warm_client_config(&cert);
    let mut group = c.benchmark_group("iroh_quinn_stream_throughput_warm");
    group.sampling_mode(SamplingMode::Flat);

    for &size in &[1024, 64 * 1024, 1024 * 1024] {
        bench_warm_for_size(&rt, &mut group, &server_config, &client_config, size);
    }

    group.finish();
}

/// Run the warm throughput benchmark for a single payload size.
///
/// Uses `iter_custom` to exclude connection re-establishment time
/// from the measurement. Only stream I/O is timed.
fn bench_warm_for_size(
    rt: &tokio::runtime::Runtime,
    group: &mut criterion::BenchmarkGroup<'_, criterion::measurement::WallTime>,
    server_config: &ServerConfig,
    client_config: &ClientConfig,
    size: usize,
) {
    group.throughput(Throughput::Bytes(size as u64));
    let sc = server_config.clone();
    let cc = client_config.clone();
    group.bench_with_input(
        BenchmarkId::from_parameter(format_size(size)),
        &size,
        |b, &payload_size| {
            // iroh-quinn needs a tokio runtime context for endpoint creation.
            let _guard = rt.enter();
            let (server, server_addr) = start_server(sc.clone());
            let client = start_client(cc.clone());
            let (mut client_conn, mut server_conn) =
                rt.block_on(establish_pair(&server, &client, server_addr));

            b.iter_custom(|iters| {
                warm_iter_custom(
                    rt,
                    iters,
                    &server,
                    &client,
                    server_addr,
                    &mut client_conn,
                    &mut server_conn,
                    payload_size,
                )
            });
        },
    );
}

/// Run `iters` warm echo iterations, timing only stream I/O.
///
/// Proactively refreshes the connection every [`WARM_CONN_LIFETIME`]
/// iterations and also on unexpected closure. Reconnection time
/// is excluded from the returned duration.
#[allow(clippy::too_many_arguments)]
fn warm_iter_custom(
    rt: &tokio::runtime::Runtime,
    iters: u64,
    server: &Endpoint,
    client: &Endpoint,
    server_addr: SocketAddr,
    client_conn: &mut Connection,
    server_conn: &mut Connection,
    payload_size: usize,
) -> Duration {
    rt.block_on(warm_iter_loop(
        iters,
        server,
        client,
        server_addr,
        client_conn,
        server_conn,
        payload_size,
    ))
}

/// Async inner loop for warm iterations to avoid repeated `block_on` calls.
#[allow(clippy::too_many_arguments)]
async fn warm_iter_loop(
    iters: u64,
    server: &Endpoint,
    client: &Endpoint,
    server_addr: SocketAddr,
    client_conn: &mut Connection,
    server_conn: &mut Connection,
    payload_size: usize,
) -> Duration {
    let payload = vec![0xABu8; payload_size];
    let mut total = Duration::ZERO;
    let mut done: u64 = 0;
    let mut conn_iter: u64 = 0;

    while done < iters {
        if conn_iter >= WARM_CONN_LIFETIME {
            let (cc, sc) = establish_pair(server, client, server_addr).await;
            *client_conn = cc;
            *server_conn = sc;
            conn_iter = 0;
        }

        let start = std::time::Instant::now();
        let ok = warm_echo_iter(client_conn, server_conn, &payload).await;
        if ok {
            total += start.elapsed();
            done += 1;
            conn_iter += 1;
        } else {
            let (cc, sc) = establish_pair(server, client, server_addr).await;
            *client_conn = cc;
            *server_conn = sc;
            conn_iter = 0;
        }
    }
    total
}

/// One warm-connection echo iteration (no handshake overhead).
///
/// The client write is spawned so that the server can `accept_bi`
/// concurrently. Returns `false` if the connection is closed.
async fn warm_echo_iter(
    client_conn: &Connection,
    server_conn: &Connection,
    payload: &[u8],
) -> bool {
    let (mut client_send, mut client_recv) = match client_conn.open_bi().await {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    let sc = server_conn.clone();
    let p = payload.to_vec();
    let write_task = tokio::spawn(async move {
        client_send.write_all(&p).await.ok();
        client_send.finish().ok();
    });

    let (mut srv_send, mut srv_recv) = match sc.accept_bi().await {
        Ok(pair) => pair,
        Err(_) => {
            let _ = write_task.await;
            return false;
        }
    };
    let data = match srv_recv.read_to_end(2_000_000).await {
        Ok(d) => d,
        Err(_) => {
            let _ = write_task.await;
            return false;
        }
    };
    if srv_send.write_all(&data).await.is_err() {
        let _ = write_task.await;
        return false;
    }
    srv_send.finish().ok();

    let _ = write_task.await;
    let received = match client_recv.read_to_end(2_000_000).await {
        Ok(d) => d,
        Err(_) => return false,
    };
    std::hint::black_box(&received);
    assert_eq!(received.len(), payload.len(), "echo size mismatch");
    true
}

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(15))
        .warm_up_time(Duration::from_secs(3));
    targets =
        bench_iroh_quinn_handshake,
        bench_iroh_quinn_stream_throughput,
        bench_iroh_quinn_datagram_throughput
}

criterion_group! {
    name = benches_warm;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(1));
    targets = bench_iroh_quinn_stream_throughput_warm
}

criterion_main!(benches, benches_warm);
