//! Integration tests for the tquic tokio async adapter.
//!
//! Validates end-to-end QUIC communication: client connects to server,
//! exchanges data via bidirectional streams and unreliable datagrams.

#![cfg(feature = "tokio-runtime")]

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use tokio::time::timeout;

use tquic::tokio_adapter::{RecvStream, SendStream, TquicConnection, TquicEndpoint};
use tquic::{Config, TlsConfig};

/// Test timeout to prevent hanging if something goes wrong.
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

/// Size of the read buffer used in stream reads.
const READ_BUF_SIZE: usize = 4096;

/// Brief delay for handshake completion on localhost.
const HANDSHAKE_DELAY: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------
// TLS / Config helpers
// ---------------------------------------------------------------------------

/// Build a tquic `Config` for either client or server.
///
/// Server configs load test certificates from `src/tls/testdata/`.
/// Client configs use default (no cert verification) for localhost testing.
fn make_config(is_server: bool) -> Result<Config, Box<dyn std::error::Error>> {
    let mut conf = Config::new()?;
    conf.set_max_idle_timeout(30_000);
    conf.set_recv_udp_payload_size(1350);
    conf.set_initial_max_data(10_000_000);
    conf.set_initial_max_stream_data_bidi_local(1_000_000);
    conf.set_initial_max_stream_data_bidi_remote(1_000_000);
    conf.set_initial_max_stream_data_uni(1_000_000);
    conf.set_initial_max_streams_bidi(100);
    conf.set_initial_max_streams_uni(100);
    conf.set_max_datagram_frame_size(65535);

    let alpn = vec![b"test".to_vec()];
    let tls_config = if is_server {
        TlsConfig::new_server_config(
            "src/tls/testdata/cert.crt",
            "src/tls/testdata/cert.key",
            alpn,
            false,
        )?
    } else {
        TlsConfig::new_client_config(alpn, false)?
    };
    conf.set_tls_config(tls_config);
    Ok(conf)
}

/// Localhost address with OS-assigned port.
fn localhost_any() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

// ---------------------------------------------------------------------------
// Stream I/O helpers
// ---------------------------------------------------------------------------

/// Write a complete message to a send stream and signal FIN.
async fn write_message(send: &SendStream, msg: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    send.write_all(msg).await?;
    send.finish().await?;
    Ok(())
}

/// Read all data from a recv stream until FIN, returning the collected bytes.
async fn read_to_end(recv: &RecvStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    let mut buf = [0u8; READ_BUF_SIZE];
    loop {
        match recv.read(&mut buf).await? {
            Some(n) => result.extend_from_slice(&buf[..n]),
            None => return Ok(result),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection setup helpers
// ---------------------------------------------------------------------------

/// Start a server endpoint and return it along with the bound address.
async fn start_server() -> Result<(TquicEndpoint, SocketAddr), Box<dyn std::error::Error>> {
    let config = make_config(true)?;
    let endpoint = TquicEndpoint::server(localhost_any(), config).await?;
    let addr = endpoint.local_addr();
    Ok((endpoint, addr))
}

/// Start a client endpoint bound to a random port.
async fn start_client() -> Result<TquicEndpoint, Box<dyn std::error::Error>> {
    let config = make_config(false)?;
    let endpoint = TquicEndpoint::client(localhost_any(), config).await?;
    Ok(endpoint)
}

/// Establish a client-server connection pair.
///
/// Returns (client_conn, server_conn). A short delay ensures the
/// QUIC handshake completes on localhost before returning.
async fn establish_pair(
    server: &mut TquicEndpoint,
    client: &TquicEndpoint,
    server_addr: SocketAddr,
) -> Result<(TquicConnection, TquicConnection), Box<dyn std::error::Error>> {
    let (client_result, server_opt) =
        tokio::join!(client.connect(server_addr, "localhost"), server.accept());
    let client_conn = client_result?;
    let server_conn = server_opt.ok_or("server accept returned None")?;

    // Allow driver threads to complete the TLS handshake.
    tokio::time::sleep(HANDSHAKE_DELAY).await;

    Ok((client_conn, server_conn))
}

// ---------------------------------------------------------------------------
// Test 1: Bidirectional stream round-trip
// ---------------------------------------------------------------------------

/// Validates that a client can connect, open a bidi stream, send data,
/// and receive a response from the server through the same stream.
#[tokio::test]
async fn test_client_server_stream_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    timeout(TEST_TIMEOUT, stream_roundtrip_inner()).await?
}

async fn stream_roundtrip_inner() -> Result<(), Box<dyn std::error::Error>> {
    let (mut server, server_addr) = start_server().await?;
    let client = start_client().await?;
    let (client_conn, mut server_conn) = establish_pair(&mut server, &client, server_addr).await?;

    let client_msg = b"hello from client";
    let server_msg = b"hello from server";

    // Client: open bidi stream and send data with FIN.
    let (client_send, client_recv) = client_conn.open_bi().await?;
    write_message(&client_send, client_msg).await?;

    // Server: accept the incoming bidi stream and read all data.
    let (server_send, server_recv) = server_conn
        .accept_bi()
        .await
        .ok_or("server did not receive bidi stream")?;

    let received = read_to_end(&server_recv).await?;
    assert_eq!(received, client_msg, "server should receive client message");

    // Server: send response with FIN.
    write_message(&server_send, server_msg).await?;

    // Client: read the server response.
    let response = read_to_end(&client_recv).await?;
    assert_eq!(
        response, server_msg,
        "client should receive server response"
    );

    client_conn.close(0, b"done");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: Datagram round-trip
// ---------------------------------------------------------------------------

/// Validates unreliable datagram exchange between client and server.
///
/// Datagrams are sent via QUIC DATAGRAM frames (RFC 9221).
/// Uses small delays to allow driver processing between send/recv.
#[tokio::test]
async fn test_datagram_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
    timeout(TEST_TIMEOUT, datagram_roundtrip_inner()).await?
}

async fn datagram_roundtrip_inner() -> Result<(), Box<dyn std::error::Error>> {
    let (mut server, server_addr) = start_server().await?;
    let client = start_client().await?;
    let (client_conn, server_conn) = establish_pair(&mut server, &client, server_addr).await?;

    let client_dgram = Bytes::from_static(b"datagram from client");
    let server_dgram = Bytes::from_static(b"datagram from server");

    // Client sends a datagram.
    client_conn.send_datagram(client_dgram.clone()).await?;

    // Allow the driver to deliver the packet to the server.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Server reads the datagram and sends one back.
    let received = server_conn.read_datagram().await?;
    assert_eq!(
        received, client_dgram,
        "server should receive client datagram"
    );

    server_conn.send_datagram(server_dgram.clone()).await?;

    // Allow the driver to deliver the packet to the client.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Client reads the server datagram.
    let response = client_conn.read_datagram().await?;
    assert_eq!(
        response, server_dgram,
        "client should receive server datagram"
    );

    client_conn.close(0, b"done");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: Multiple concurrent bidi streams
// ---------------------------------------------------------------------------

/// Validates that multiple bidirectional streams can carry independent
/// data over the same QUIC connection without interference.
#[tokio::test]
async fn test_multiple_streams() -> Result<(), Box<dyn std::error::Error>> {
    timeout(TEST_TIMEOUT, multiple_streams_inner()).await?
}

async fn multiple_streams_inner() -> Result<(), Box<dyn std::error::Error>> {
    let (mut server, server_addr) = start_server().await?;
    let client = start_client().await?;
    let (client_conn, mut server_conn) = establish_pair(&mut server, &client, server_addr).await?;

    let stream_count = 5;

    // Client: open N bidi streams and send unique data on each.
    let mut client_recvs = Vec::with_capacity(stream_count);
    for i in 0..stream_count {
        let msg = format!("stream-{i}-payload");
        let (send, recv) = client_conn.open_bi().await?;
        write_message(&send, msg.as_bytes()).await?;
        client_recvs.push((i, recv));
    }

    // Server: accept N streams, read data, echo with a prefix.
    for _ in 0..stream_count {
        let (srv_send, srv_recv) = server_conn
            .accept_bi()
            .await
            .ok_or("server did not receive expected bidi stream")?;

        let data = read_to_end(&srv_recv).await?;
        let reply = format!("echo:{}", String::from_utf8_lossy(&data));
        write_message(&srv_send, reply.as_bytes()).await?;
    }

    // Client: verify each response matches the expected echo.
    for (i, recv) in &client_recvs {
        let response = read_to_end(recv).await?;
        let expected = format!("echo:stream-{i}-payload");
        assert_eq!(
            response,
            expected.as_bytes(),
            "stream {i} response mismatch"
        );
    }

    client_conn.close(0, b"done");
    Ok(())
}
