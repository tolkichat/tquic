//! Benchmarks for the tquic tokio async adapter.
//!
//! Measures handshake latency, bidirectional stream throughput,
//! and datagram throughput over localhost QUIC connections.

#![cfg(feature = "tokio-runtime")]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};

use tquic::tokio_adapter::{RecvStream, SendStream, TquicConnection, TquicEndpoint};
use tquic::{Config, TlsConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Read buffer size for stream operations.
const READ_BUF_SIZE: usize = 65536;

/// Maximum time to wait for datagram drain on localhost.
const DGRAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

// ---------------------------------------------------------------------------
// TLS / Config helpers
// ---------------------------------------------------------------------------

/// Build a tquic `Config` for benchmarking.
///
/// Server configs load test certificates; client configs skip verification.
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
    conf.set_initial_max_data(10_000_000);
    conf.set_initial_max_stream_data_bidi_local(1_000_000);
    conf.set_initial_max_stream_data_bidi_remote(1_000_000);
    conf.set_initial_max_stream_data_uni(1_000_000);
    conf.set_initial_max_streams_bidi(100);
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

/// Localhost address with OS-assigned port.
fn localhost_any() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

// ---------------------------------------------------------------------------
// Connection setup helpers
// ---------------------------------------------------------------------------

/// Start a server endpoint from a pre-built config.
async fn start_server(config: Config) -> (TquicEndpoint, SocketAddr) {
    let endpoint = TquicEndpoint::server(localhost_any(), config)
        .await
        .expect("server endpoint creation");
    let addr = endpoint.local_addr();
    (endpoint, addr)
}

/// Start a client endpoint from a pre-built config.
async fn start_client(config: Config) -> TquicEndpoint {
    TquicEndpoint::client(localhost_any(), config)
        .await
        .expect("client endpoint creation")
}

/// Establish a client-server connection pair with completed handshake.
async fn establish_pair(
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
) -> (TquicConnection, TquicConnection) {
    let (client_result, server_opt) =
        tokio::join!(client.connect(server_addr, "localhost"), server.accept());
    let client_conn = client_result.expect("client connect");
    let server_conn = server_opt.expect("server accept");
    wait_for_handshake(&client_conn, &server_conn).await;
    (client_conn, server_conn)
}

/// Wait for both sides of the handshake to complete.
async fn wait_for_handshake(client: &TquicConnection, server: &TquicConnection) {
    tokio::try_join!(client.established(), server.established()).expect("handshake failed");
}

// ---------------------------------------------------------------------------
// Stream I/O helpers
// ---------------------------------------------------------------------------

/// Write all data and signal FIN on a send stream.
async fn write_and_finish(send: &SendStream, data: &[u8]) {
    send.write_all(data).await.expect("stream write_all");
    send.finish().await.expect("stream finish");
}

/// Read all data from a recv stream until FIN.
async fn read_to_end(recv: &RecvStream) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buf = [0u8; READ_BUF_SIZE];
    loop {
        match recv.read(&mut buf).await.expect("stream read") {
            Some(n) => result.extend_from_slice(&buf[..n]),
            None => return result,
        }
    }
}

// ---------------------------------------------------------------------------
// Echo server helpers
// ---------------------------------------------------------------------------

/// Run an echo server that accepts one bidi stream and echoes data back.
async fn echo_one_stream(mut server_conn: TquicConnection) {
    let (srv_send, srv_recv) = server_conn
        .accept_bi()
        .await
        .expect("server accept_bi for echo");
    let data = read_to_end(&srv_recv).await;
    write_and_finish(&srv_send, &data).await;
}

/// Run a datagram sink that reads `count` datagrams from a connection.
///
/// Tolerates connection closure (datagrams are unreliable).
/// Returns the number of datagrams successfully received.
async fn drain_datagrams(conn: &TquicConnection, count: usize) -> usize {
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
/// BoringSSL certificate loading (~18 ms) is not measured.
fn bench_handshake(c: &mut Criterion) {
    let rt = bench_runtime();
    let server_config = make_config(true);
    let client_config = make_config(false);

    c.bench_function("handshake", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut server, server_addr) = start_server(server_config.clone()).await;
                let client = start_client(client_config.clone()).await;
                let (client_conn, _server_conn) =
                    establish_pair(&mut server, &client, server_addr).await;
                std::hint::black_box(&client_conn);
                client_conn.close(0, b"done");
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
fn bench_stream_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let server_config = make_config(true);
    let client_config = make_config(false);
    let mut group = c.benchmark_group("stream_throughput");
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
                    rt.block_on(async {
                        run_stream_throughput_iter(sc.clone(), cc.clone(), payload_size).await;
                    });
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
async fn run_stream_throughput_iter(
    server_config: Config,
    client_config: Config,
    payload_size: usize,
) {
    let (mut server, server_addr) = start_server(server_config).await;
    let client = start_client(client_config).await;
    let (client_conn, server_conn) = establish_pair(&mut server, &client, server_addr).await;

    let echo_task = tokio::spawn(echo_one_stream(server_conn));

    let payload = vec![0xABu8; payload_size];
    let (client_send, client_recv) = client_conn.open_bi().await.expect("open_bi");
    write_and_finish(&client_send, &payload).await;
    let received = read_to_end(&client_recv).await;

    std::hint::black_box(&received);
    assert_eq!(received.len(), payload_size, "echo size mismatch");

    client_conn.close(0, b"done");
    let _ = echo_task.await;
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Datagram throughput
// ---------------------------------------------------------------------------

/// Measure datagram send throughput at various batch sizes.
///
/// TLS configs are pre-built outside the iteration loop.
fn bench_datagram_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let server_config = make_config(true);
    let client_config = make_config(false);
    let mut group = c.benchmark_group("datagram_throughput");
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
                    rt.block_on(async {
                        run_datagram_throughput_iter(sc.clone(), cc.clone(), dgram_count as usize)
                            .await;
                    });
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
async fn run_datagram_throughput_iter(server_config: Config, client_config: Config, count: usize) {
    let (mut server, server_addr) = start_server(server_config).await;
    let client = start_client(client_config).await;
    let (client_conn, server_conn) = establish_pair(&mut server, &client, server_addr).await;

    let drain_task = tokio::spawn(async move { drain_datagrams(&server_conn, count).await });

    let dgram_payload = Bytes::from(vec![0xCDu8; 1200]);
    send_datagrams(&client_conn, &dgram_payload, count).await;

    // Brief yield to let the driver flush remaining packets on localhost.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Best-effort wait: datagrams are unreliable, so don't panic on timeout.
    let received = tokio::time::timeout(DGRAM_DRAIN_TIMEOUT, drain_task)
        .await
        .ok()
        .and_then(|r| r.ok())
        .unwrap_or(0);
    std::hint::black_box(received);
    client_conn.close(0, b"done");
}

/// Send `count` datagrams with a small yield between batches.
async fn send_datagrams(conn: &TquicConnection, payload: &Bytes, count: usize) {
    for i in 0..count {
        conn.send_datagram(payload.clone())
            .await
            .expect("datagram send");
        // Yield periodically to let the driver flush packets.
        if i % 10 == 9 {
            tokio::task::yield_now().await;
        }
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
    targets = bench_handshake, bench_stream_throughput, bench_datagram_throughput
}
criterion_main!(benches);
