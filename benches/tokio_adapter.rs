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

use tquic::tokio_adapter::{AsyncError, RecvStream, SendStream, TquicConnection, TquicEndpoint};
use tquic::{Config, TlsConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Read buffer size for stream operations.
const READ_BUF_SIZE: usize = 65536;

/// Larger read buffer for throughput benchmarks (2 MB).
///
/// A 2 MB heap buffer reduces per-1 MB transfer from 16 reads to 1,
/// avoiding loop overhead and `extend_from_slice` copies.
const THROUGHPUT_READ_BUF_SIZE: usize = 2 * 1024 * 1024;

/// Maximum time to wait for datagram drain on localhost.
const DGRAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Maximum stream iterations per connection before proactive refresh.
///
/// tquic connections degrade after many rapid stream cycles
/// (accumulated stream state, flow-control updates). Refreshing
/// every N iterations avoids random mid-sample failures while
/// keeping reconnection cost out of the measurement.
const WARM_CONN_LIFETIME: u64 = 50;

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
    // Large windows to support warm-connection benchmarks (many iterations).
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
async fn write_and_finish(send: &SendStream, data: &[u8]) -> Result<(), AsyncError> {
    send.write_all(data).await?;
    send.finish().await
}

/// Read all data from a recv stream until FIN using a small stack buffer.
async fn read_to_end(recv: &RecvStream) -> Result<Vec<u8>, AsyncError> {
    read_to_end_with_buf(recv, READ_BUF_SIZE).await
}

/// Read all data from a recv stream using a large heap buffer.
///
/// The 2 MB buffer reduces per-1 MB transfer from 16 reads to 1,
/// cutting loop overhead and `extend_from_slice` copies.
async fn read_to_end_large(recv: &RecvStream) -> Result<Vec<u8>, AsyncError> {
    read_to_end_with_buf(recv, THROUGHPUT_READ_BUF_SIZE).await
}

/// Read all data from a recv stream until FIN.
///
/// Uses a heap-allocated buffer of the given size to avoid
/// stack overflow with large buffers.
async fn read_to_end_with_buf(recv: &RecvStream, buf_size: usize) -> Result<Vec<u8>, AsyncError> {
    let mut result = Vec::new();
    let mut buf = vec![0u8; buf_size];
    loop {
        match recv.read(&mut buf).await? {
            Some(n) => result.extend_from_slice(&buf[..n]),
            None => return Ok(result),
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
    let data = read_to_end(&srv_recv).await.expect("cold echo read");
    write_and_finish(&srv_send, &data)
        .await
        .expect("cold echo write");
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
/// Endpoints are pre-built outside the iteration loop so that
/// UDP socket bind + driver spawn + BoringSSL cert loading are not measured.
fn bench_handshake(c: &mut Criterion) {
    let rt = bench_runtime();
    let server_config = make_config(true);
    let client_config = make_config(false);

    c.bench_function("handshake", |b| {
        let (mut server, server_addr) = rt.block_on(start_server(server_config.clone()));
        let client = rt.block_on(start_client(client_config.clone()));

        b.iter(|| {
            rt.block_on(async {
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
/// Endpoints are pre-built outside the iteration loop for fair measurement.
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
                let (mut server, server_addr) = rt.block_on(start_server(sc.clone()));
                let client = rt.block_on(start_client(cc.clone()));

                b.iter(|| {
                    rt.block_on(async {
                        stream_throughput_iter(&mut server, &client, server_addr, payload_size)
                            .await;
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

/// Run a single stream throughput iteration on pre-built endpoints.
///
/// Establishes a connection, spawns an echo server,
/// writes `payload_size` bytes and reads the echo back.
async fn stream_throughput_iter(
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
    payload_size: usize,
) {
    let (client_conn, server_conn) = establish_pair(server, client, server_addr).await;

    let echo_task = tokio::spawn(echo_one_stream(server_conn));

    let payload = vec![0xABu8; payload_size];
    let (client_send, client_recv) = client_conn.open_bi().await.expect("open_bi");
    write_and_finish(&client_send, &payload)
        .await
        .expect("cold bench write");
    let received = read_to_end(&client_recv).await.expect("cold bench read");

    std::hint::black_box(&received);
    assert_eq!(received.len(), payload_size, "echo size mismatch");

    client_conn.close(0, b"done");
    let _ = echo_task.await;
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Stream throughput (warm connection)
// ---------------------------------------------------------------------------

/// Measure stream throughput with a pre-established connection.
///
/// Unlike [`bench_stream_throughput`], the QUIC handshake happens once
/// *before* the benchmark loop. Each iteration only measures:
/// `open_bi -> write -> server echo -> read`.
fn bench_stream_throughput_warm(c: &mut Criterion) {
    let rt = bench_runtime();
    let server_config = make_config(true);
    let client_config = make_config(false);
    let mut group = c.benchmark_group("stream_throughput_warm");
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
    server_config: &Config,
    client_config: &Config,
    size: usize,
) {
    group.throughput(Throughput::Bytes(size as u64));
    let sc = server_config.clone();
    let cc = client_config.clone();
    group.bench_with_input(
        BenchmarkId::from_parameter(format_size(size)),
        &size,
        |b, &payload_size| {
            let (mut server, server_addr) = rt.block_on(start_server(sc.clone()));
            let client = rt.block_on(start_client(cc.clone()));
            let (mut client_conn, mut server_conn) =
                rt.block_on(establish_pair(&mut server, &client, server_addr));

            b.iter_custom(|iters| {
                warm_iter_custom(
                    rt,
                    iters,
                    &mut server,
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
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
    client_conn: &mut TquicConnection,
    server_conn: &mut TquicConnection,
    payload_size: usize,
) -> Duration {
    let mut total = Duration::ZERO;
    let mut done: u64 = 0;
    let mut conn_iter: u64 = 0;

    while done < iters {
        // Proactive refresh to avoid degraded connections.
        if conn_iter >= WARM_CONN_LIFETIME {
            reconnect(rt, server, client, server_addr, client_conn, server_conn);
            conn_iter = 0;
        }

        let start = std::time::Instant::now();
        let ok = rt.block_on(warm_echo_iter(client_conn, server_conn, payload_size));
        if ok {
            total += start.elapsed();
            done += 1;
            conn_iter += 1;
        } else {
            reconnect(rt, server, client, server_addr, client_conn, server_conn);
            conn_iter = 0;
        }
    }
    total
}

/// Re-establish client and server connections (untimed).
fn reconnect(
    rt: &tokio::runtime::Runtime,
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
    client_conn: &mut TquicConnection,
    server_conn: &mut TquicConnection,
) {
    let (cc, sc) = rt.block_on(establish_pair(server, client, server_addr));
    *client_conn = cc;
    *server_conn = sc;
}

/// One warm-connection echo iteration (no handshake overhead).
///
/// The client write is spawned so that the server can `accept_bi`
/// concurrently. The server echoes data back inline, then the
/// client reads the echo.
async fn warm_echo_iter(
    client_conn: &TquicConnection,
    server_conn: &mut TquicConnection,
    payload_size: usize,
) -> bool {
    let payload = vec![0xABu8; payload_size];

    // Client opens a stream; if connection is closed, signal caller.
    let (client_send, client_recv) = match client_conn.open_bi().await {
        Ok(pair) => pair,
        Err(_) => return false,
    };

    // Spawn the client write so the server can accept concurrently.
    let write_task = tokio::spawn(async move {
        let _ = write_and_finish(&client_send, &payload).await;
    });

    // Server accepts the peer-initiated stream and echoes data back.
    let (srv_send, srv_recv) = match server_conn.accept_bi().await {
        Some(pair) => pair,
        None => {
            let _ = write_task.await;
            return false;
        }
    };
    let data = match read_to_end_large(&srv_recv).await {
        Ok(d) => d,
        Err(_) => {
            let _ = write_task.await;
            return false;
        }
    };
    if write_and_finish(&srv_send, &data).await.is_err() {
        let _ = write_task.await;
        return false;
    }

    // Client waits for write to finish, then reads the echo.
    let _ = write_task.await;
    let received = match read_to_end_large(&client_recv).await {
        Ok(d) => d,
        Err(_) => return false,
    };
    std::hint::black_box(&received);
    assert_eq!(received.len(), payload_size, "echo size mismatch");
    true
}

// ---------------------------------------------------------------------------
// Benchmark group 4: Datagram throughput
// ---------------------------------------------------------------------------

/// Measure datagram send throughput at various batch sizes.
///
/// Endpoints are pre-built outside the iteration loop for fair measurement.
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
                let (mut server, server_addr) = rt.block_on(start_server(sc.clone()));
                let client = rt.block_on(start_client(cc.clone()));

                b.iter(|| {
                    rt.block_on(async {
                        datagram_throughput_iter(
                            &mut server,
                            &client,
                            server_addr,
                            dgram_count as usize,
                        )
                        .await;
                    });
                });
            },
        );
    }

    group.finish();
}

/// Run a single datagram throughput iteration on pre-built endpoints.
///
/// Establishes a connection, sends `count` datagrams from client,
/// and drains them on the server side. The drain is best-effort
/// since QUIC datagrams are unreliable.
async fn datagram_throughput_iter(
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
    count: usize,
) {
    let (client_conn, server_conn) = establish_pair(server, client, server_addr).await;

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

criterion_group! {
    name = benches_warm;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(1));
    targets = bench_stream_throughput_warm
}

criterion_main!(benches, benches_warm);
