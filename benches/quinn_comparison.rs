//! Quinn comparison benchmarks for side-by-side tquic performance analysis.
//!
//! Measures the same three scenarios as `tokio_adapter.rs`:
//!   1. Handshake latency (connect + established)
//!   2. Bidirectional stream throughput (1 KB, 64 KB, 1 MB)
//!   3. Datagram throughput (10, 100, 1000 x 1200 B)
//!
//! Run both benchmarks for comparison:
//! ```bash
//! cargo bench -p tquic --features tokio-runtime --bench tokio_adapter
//! cargo bench -p tquic --bench quinn_comparison
//! ```

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig, VarInt};
use rcgen::CertifiedKey;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

// ---------------------------------------------------------------------------
// Constants (same as tokio_adapter.rs)
// ---------------------------------------------------------------------------

/// Maximum datagram payload (matches tquic benchmark).
const DATAGRAM_PAYLOAD_SIZE: usize = 1200;

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

/// Build a Quinn `TransportConfig` matching tquic benchmark parameters.
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

/// Build a Quinn `ServerConfig` with self-signed cert.
fn make_server_config(cert: &BenchCert) -> ServerConfig {
    let mut config = ServerConfig::with_single_cert(
        vec![cert.cert_der.clone()],
        cert.key_der.clone_key().into(),
    )
    .expect("server config from self-signed cert");
    config.transport_config(Arc::new(bench_transport_config()));
    config
}

/// Build a Quinn `ClientConfig` trusting the bench cert.
fn make_client_config(cert: &BenchCert) -> ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
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

/// Start a Quinn server endpoint from a pre-built config.
fn start_server(config: ServerConfig) -> (Endpoint, SocketAddr) {
    let endpoint =
        Endpoint::server(config, localhost_any()).expect("quinn server endpoint creation");
    let addr = endpoint.local_addr().expect("server local addr");
    (endpoint, addr)
}

/// Start a Quinn client endpoint from a pre-built config.
fn start_client(config: ClientConfig) -> Endpoint {
    let mut endpoint = Endpoint::client(localhost_any()).expect("quinn client endpoint creation");
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
) -> (quinn::Connection, quinn::Connection) {
    // Spawn accept on a background task so the server endpoint's
    // I/O driver runs concurrently with the client handshake.
    let server_handle = server.clone();
    let accept_task = tokio::spawn(async move {
        let incoming = server_handle
            .accept()
            .await
            .expect("server incoming connection");
        incoming.await.expect("server connection established")
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

/// Write all data and signal FIN on a Quinn send stream.
async fn write_and_finish(send: &mut quinn::SendStream, data: &[u8]) {
    send.write_all(data).await.expect("stream write_all");
    send.finish().expect("stream finish");
}

/// Read all data from a Quinn recv stream until FIN.
async fn read_to_end(recv: &mut quinn::RecvStream, size_limit: usize) -> Vec<u8> {
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
/// Dropping a Quinn `Connection` triggers an immediate close, which would
/// race with the client's `read_to_end`.
async fn echo_one_stream(server_conn: quinn::Connection) -> quinn::Connection {
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
async fn drain_datagrams(conn: &quinn::Connection, count: usize) -> usize {
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

// ---------------------------------------------------------------------------
// Benchmark group 1: Handshake
// ---------------------------------------------------------------------------

/// Measure the time to establish a QUIC connection (connect + handshake).
///
/// TLS configs are pre-built outside the iteration loop so that
/// certificate generation cost is not measured.
fn bench_quinn_handshake(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);

    c.bench_function("quinn_handshake", |b| {
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
// Benchmark group 2: Stream throughput
// ---------------------------------------------------------------------------

/// Measure bidirectional stream throughput at various payload sizes.
///
/// TLS configs are pre-built outside the iteration loop.
fn bench_quinn_stream_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);
    let mut group = c.benchmark_group("quinn_stream_throughput");
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

/// Format a byte size as a human-readable label.
fn format_size(bytes: usize) -> String {
    match bytes {
        n if n >= 1024 * 1024 => format!("{}MB", n / (1024 * 1024)),
        n if n >= 1024 => format!("{}KB", n / 1024),
        n => format!("{}B", n),
    }
}

/// Run a single stream throughput iteration.
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
///
/// TLS configs are pre-built outside the iteration loop.
fn bench_quinn_datagram_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let server_config = make_server_config(&cert);
    let client_config = make_client_config(&cert);
    let mut group = c.benchmark_group("quinn_datagram_throughput");
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
/// and drains them on the server side. The drain is best-effort
/// since QUIC datagrams are unreliable.
async fn run_datagram_iter(server_config: ServerConfig, client_config: ClientConfig, count: usize) {
    let (server, server_addr) = start_server(server_config);
    let client = start_client(client_config);
    let (client_conn, server_conn) = establish_pair(&server, &client, server_addr).await;

    let drain_task = tokio::spawn(async move { drain_datagrams(&server_conn, count).await });

    let dgram_payload = Bytes::from(vec![0xCDu8; DATAGRAM_PAYLOAD_SIZE]);
    send_datagrams(&client_conn, &dgram_payload, count);

    // Give the driver time to deliver packets on localhost.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Best-effort wait: datagrams are unreliable, so don't panic on timeout.
    let received = tokio::time::timeout(Duration::from_secs(3), drain_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    std::hint::black_box(received);
    client_conn.close(0u32.into(), b"done");
}

/// Send `count` datagrams synchronously (Quinn's send_datagram is sync).
fn send_datagrams(conn: &quinn::Connection, payload: &Bytes, count: usize) {
    for _ in 0..count {
        // Quinn's send_datagram is synchronous and returns immediately.
        // It may fail under congestion; ignore errors to match tquic
        // benchmark's best-effort semantics.
        let _ = conn.send_datagram(payload.clone());
    }
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
        bench_quinn_handshake,
        bench_quinn_stream_throughput,
        bench_quinn_datagram_throughput
}
criterion_main!(benches);
