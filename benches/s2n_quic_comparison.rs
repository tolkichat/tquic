//! Benchmarks for s2n-quic -- direct comparison with tquic tokio adapter benchmarks.
//!
//! Measures the same three scenarios:
//! 1. Handshake latency
//! 2. Bidirectional stream throughput (echo pattern)
//! 3. Datagram throughput (skipped -- s2n-quic datagram API is unstable)
//!
//! Run all three implementations for comparison:
//! ```bash
//! cargo bench -p tquic --features tokio-runtime --bench tokio_adapter
//! cargo bench -p tquic --bench quinn_comparison
//! cargo bench -p tquic --bench s2n_quic_comparison
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use criterion::{
    criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode, Throughput,
};
use s2n_quic::client::Connect;
use s2n_quic::{Client, Server};

// ---------------------------------------------------------------------------
// TLS helpers (generate self-signed certs at runtime via rcgen)
// ---------------------------------------------------------------------------

/// PEM-encoded certificate and key pair for benchmark TLS.
struct BenchCert {
    cert_pem: String,
    key_pem: String,
}

/// Generate a self-signed certificate for "localhost" using rcgen.
///
/// s2n-quic verifies server names, so the cert must match the SNI
/// we use in `Connect::new(...).with_server_name("localhost")`.
fn generate_bench_cert() -> BenchCert {
    let certified_key = rcgen::generate_simple_self_signed(vec!["localhost".into()])
        .expect("self-signed cert generation");
    BenchCert {
        cert_pem: certified_key.cert.pem(),
        key_pem: certified_key.key_pair.serialize_pem(),
    }
}

// ---------------------------------------------------------------------------
// Server / Client builders
// ---------------------------------------------------------------------------

/// Start an s2n-quic server bound to a random localhost port.
///
/// Returns the `Server` acceptor and the address it is listening on.
async fn start_server(cert: &BenchCert) -> (Server, SocketAddr) {
    let server = Server::builder()
        .with_tls((cert.cert_pem.as_str(), cert.key_pem.as_str()))
        .expect("server TLS config")
        .with_io("127.0.0.1:0")
        .expect("server IO bind")
        .start()
        .expect("server start");
    let addr = server.local_addr().expect("server local_addr");
    (server, addr)
}

/// Start an s2n-quic client that trusts the benchmark certificate.
async fn start_client(cert: &BenchCert) -> Client {
    Client::builder()
        .with_tls(cert.cert_pem.as_str())
        .expect("client TLS config")
        .with_io("0.0.0.0:0")
        .expect("client IO bind")
        .start()
        .expect("client start")
}

// ---------------------------------------------------------------------------
// Connection helpers
// ---------------------------------------------------------------------------

/// Establish a client-server connection pair.
///
/// Returns (client_connection, server_connection).
async fn establish_pair(
    server: &mut Server,
    client: &Client,
    server_addr: SocketAddr,
) -> (s2n_quic::Connection, s2n_quic::Connection) {
    let connect = Connect::new(server_addr).with_server_name("localhost");
    let (client_conn, server_conn) = tokio::join!(client.connect(connect), server.accept());
    let client_conn = client_conn.expect("client connect");
    let server_conn = server_conn.expect("server accept");
    (client_conn, server_conn)
}

// ---------------------------------------------------------------------------
// Stream I/O helpers
// ---------------------------------------------------------------------------

/// Write all data and signal finish on the send half.
async fn write_and_finish(send: &mut s2n_quic::stream::SendStream, data: &[u8]) {
    send.send(Bytes::copy_from_slice(data))
        .await
        .expect("stream send");
    send.finish().expect("stream finish");
}

/// Read all data from the receive half until the peer finishes.
async fn read_to_end(recv: &mut s2n_quic::stream::ReceiveStream) -> Vec<u8> {
    let mut result = Vec::new();
    while let Ok(Some(chunk)) = recv.receive().await {
        result.extend_from_slice(&chunk);
    }
    result
}

// ---------------------------------------------------------------------------
// Echo server helper
// ---------------------------------------------------------------------------

/// Accept one bidirectional stream, read all data, and echo it back.
async fn echo_one_stream(mut conn: s2n_quic::Connection) {
    let stream = conn
        .accept_bidirectional_stream()
        .await
        .expect("server accept_bi")
        .expect("stream should exist");
    let (mut recv, mut send) = stream.split();
    let data = read_to_end(&mut recv).await;
    write_and_finish(&mut send, &data).await;
}

// ---------------------------------------------------------------------------
// Runtime helper
// ---------------------------------------------------------------------------

/// Create a multi-threaded tokio runtime for benchmarks.
fn bench_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime creation")
}

// ---------------------------------------------------------------------------
// Format helper (same as tquic / quinn benchmarks)
// ---------------------------------------------------------------------------

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
fn bench_handshake(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();

    c.bench_function("s2n_handshake", |b| {
        let (mut server, addr) = rt.block_on(start_server(&cert));
        let client = rt.block_on(start_client(&cert));

        b.iter(|| {
            rt.block_on(async {
                let (client_conn, _server_conn) = establish_pair(&mut server, &client, addr).await;
                std::hint::black_box(&client_conn);
                client_conn.close(0u32.into());
            });
        });
    });
}

// ---------------------------------------------------------------------------
// Benchmark group 2: Stream throughput
// ---------------------------------------------------------------------------

/// Measure bidirectional stream throughput at various payload sizes.
fn bench_stream_throughput(c: &mut Criterion) {
    let rt = bench_runtime();
    let cert = generate_bench_cert();
    let mut group = c.benchmark_group("s2n_stream_throughput");
    group.sampling_mode(SamplingMode::Flat);

    for &size in &[1024, 64 * 1024, 1024 * 1024] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format_size(size)),
            &size,
            |b, &payload_size| {
                let (mut server, addr) = rt.block_on(start_server(&cert));
                let client = rt.block_on(start_client(&cert));

                b.iter(|| {
                    rt.block_on(async {
                        let (mut client_conn, server_conn) =
                            establish_pair(&mut server, &client, addr).await;
                        let echo_task = tokio::spawn(echo_one_stream(server_conn));

                        let payload = vec![0xABu8; payload_size];
                        let stream = client_conn
                            .open_bidirectional_stream()
                            .await
                            .expect("open_bidirectional_stream");
                        let (mut recv, mut send) = stream.split();

                        write_and_finish(&mut send, &payload).await;
                        let received = read_to_end(&mut recv).await;

                        std::hint::black_box(&received);
                        assert_eq!(received.len(), payload_size, "echo size mismatch");

                        client_conn.close(0u32.into());
                        let _ = echo_task.await;
                    });
                });
            },
        );
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// Benchmark group 3: Datagram throughput (skipped)
// ---------------------------------------------------------------------------

// NOTE: s2n-quic datagram support is unstable (RFC 9221).
//
// The public API exposes `connection.datagram_mut(|sender| ...)` but requires
// a custom datagram provider type -- there is no default datagram provider
// or `with_datagram()` builder method in the stable API.
//
// See: https://github.com/aws/s2n-quic/issues/1253
//
// To add datagram benchmarks once the API stabilizes:
// 1. Implement `s2n_quic::provider::datagram::Sender` and `Receiver` traits
// 2. Register via a (future) `with_datagram()` builder method
// 3. Use `connection.datagram_mut(|sender| sender.send_datagram(payload))`
//
// Until then, compare only handshake and stream throughput between
// tquic, quinn, and s2n-quic. Datagram benchmarks remain tquic/quinn-only.

// ---------------------------------------------------------------------------
// Criterion harness
// ---------------------------------------------------------------------------

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(15))
        .warm_up_time(Duration::from_secs(3));
    targets = bench_handshake, bench_stream_throughput
}
criterion_main!(benches);
