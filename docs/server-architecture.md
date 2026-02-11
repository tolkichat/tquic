# tolki-server-api: Architecture with tquic + Tokio

## Overview

tolki-server-api is a QUIC proxy server. It does NOT process business logic or store state.
All business logic lives in tolki-server-db, accessed via gRPC.

```
  iOS Client                 tolki-server-api              tolki-server-db
 (tolki-client)              (QUIC PROXY)                  (BUSINESS LOGIC)
      |                           |                              |
      |--- QUIC connection ------>|                              |
      |--- Handshake (proto) ---->|                              |
      |<-- HandshakeResponse -----|                              |
      |                           |                              |
      |--- StreamRequest -------->|--- gRPC ------------------>  |
      |<-- StreamResponse --------|<-- gRPC response ----------  |
      |                           |                              |
      |=== RTP datagrams ========>|=== forward via channels ===> |
      |<=========================.|<============================.|
```

## Startup Sequence

```
main.rs
  |
  +-- AppConfig::from_env()              # Parse CLI/env config
  +-- AppState::new()                    # Create shared state (Arc)
  +-- CancellationToken::new()           # Global shutdown signal
  |
  +-- run_health_server()                # HTTP health checks (for K8s)
  |     routing/health.rs
  |
  +-- start_sync_services()              # Background gRPC sync with registry
  |     +-- TokenSyncService::run()      # Sync auth tokens
  |     +-- UserDbSyncService::run()     # Sync user-server mappings
  |     +-- await initial sync...        # Block until first sync done
  |
  +-- run_quic_server()                  # Start QUIC accept loop
  |     transport/server.rs
  |
  +-- select! {                          # Wait for shutdown
  |     server_handle => ...,
  |     ctrl_c() => cancel_token.cancel()
  |   }
```

**Files:**
- `main.rs` -- entry point, wiring
- `core/config.rs` -- `AppConfig` (clap + env)
- `core/state.rs` -- `AppState` (Arc-wrapped shared state)

## Transport Layer

### TLS Configuration

```
transport/tls.rs
  |
  +-- make_tquic_server_config()
        |
        +-- Load or generate self-signed cert (rcgen)
        +-- TlsConfig::new_server_config()     # BoringSSL (not rustls!)
        |     alpn: ["tolki/1"]
        |     enable_early_data: true (0-RTT)
        |
        +-- tquic::Config                      # Transport parameters
              initial_max_data: 10 MB
              initial_max_stream_data_bidi: 1 MB
              max_idle_timeout: 30s
              enable_dgram: true               # RFC 9221 datagrams
              dgram_recv_max_queue_len: 128
              dgram_send_max_queue_len: 128
```

**Key:** tquic uses BoringSSL (not rustls) for TLS 1.3.
Certs are PEM-encoded to disk because BoringSSL reads from files.

### Accept Loop

```
transport/server.rs
  |
  +-- run_quic_server(&config, app, cancel_token)
        |
        +-- make_tquic_server_config()
        +-- TquicEndpoint::server(addr, config).await
        |     # Creates driver thread with LocalSet
        |     # (tquic types are !Send, use Rc<RefCell<>>)
        |     # Driver bridges callbacks to async channels
        |
        +-- accept_connections(app, &mut endpoint, signal)
              |
              loop {
                select! {
                  conn = endpoint.accept() => {
                    # TquicConnection: Send-safe handle
                    # All ops forwarded to driver via channels
                    tokio::spawn(handle_quic_connection(app, conn))
                  }
                  _ = cancel_token.cancelled() => break
                }
              }
```

**tquic driver architecture** (inside TquicEndpoint):
```
+------------------+          channels           +------------------+
|  Tokio tasks     |  ---- ConnCmd/StreamCmd ---> |  Driver thread   |
|  (Send, async)   |  <--- results via oneshot -- |  (LocalSet,      |
|                  |  <--- streams via mpsc -----  |   !Send types)   |
+------------------+                              +------------------+
                                                  |  event loop:     |
                                                  |  poll_timeout()  |
                                                  |  handle commands |
                                                  |  dispatch events |
                                                  +------------------+
```

### Connection Handshake

```
transport/connection.rs
  |
  +-- handle_quic_connection(app, conn)
        |
        +-- metrics::connection_opened()
        +-- accept_control_stream(&mut conn)
        |     # Wait for first bidi stream from client
        |     conn.accept_bi() -> (SendStream, RecvStream)
        |
        +-- timeout(5s, read_handshake(recv))      # Slowloris protection
        |     +-- read_exact(&recv, 4 bytes)         # Length prefix (BE u32)
        |     +-- validate size (0 < len <= 64KB)
        |     +-- read_exact(&recv, len bytes)
        |     +-- ConnectionHandshake::decode()       # Protobuf
        |
        +-- process_handshake(app, handshake, conn, send)
        |     +-- token.trim()
        |     +-- if token.is_empty():
        |     |     anonymous, user_id = Uuid::nil()
        |     +-- elif authenticate_from_handshake(token):
        |     |     authenticated, user_id from JWT
        |     +-- else:
        |     |     write_handshake_response(success=false, error)
        |     |     return Err(Auth)
        |     +-- write_handshake_response(success=true)
        |     |     encode proto -> write len (4B BE) -> write body
        |     |     send.finish()   # <-- FIN to prevent RESET_STREAM
        |
        +-- start_session(app, user_id, session_id, last_seq, conn)
              Session::new_quic() -> session.run()
```

**Wire format (handshake):**
```
Client -> Server:
  [4 bytes BE length][ConnectionHandshake protobuf]

Server -> Client:
  [4 bytes BE length][ConnectionHandshakeResponse protobuf]
  FIN (stream close)
```

## Session Layer

### Session Creation

```
session/session.rs
  |
  +-- Session::new_quic(app, user_id, session_id, last_seq, connection)
        |
        +-- conn.open_bi()                # Open 2nd bidi stream for data
        |     -> (send_stream, recv_stream)
        |
        +-- SessionChannels::new()        # Create kanal channels
        |     tx/rx_request   (StreamReader -> RequestRouter)
        |     tx/rx_response  (RequestRouter -> StreamWriter)
        |     tx/rx_dgram_in  (DatagramHandler -> RtpForwarder)
        |     tx/rx_dgram_out (RtpForwarder -> DatagramHandler)
        |
        +-- SessionShared::new()          # Shared mutable state (Arc)
        |     user_id, session_id, app, db_connection, send_streams
        |
        +-- CancellationToken::new()      # Per-session cancellation
        +-- SessionConfig::default()
```

### Session Task Supervision (fail-fast select!)

```
session.run()
  |
  +-- SessionTaskSpawner::new(session, config)
  |
  +-- spawn 6 concurrent tasks:
  |
  |   [1] StreamReader       reads proto from RecvStream -> tx_request
  |   [2] StreamWriter       rx_response -> writes proto to SendStream
  |   [3] DatagramHandler    read_datagram/send_datagram (RTP)
  |   [4] RequestRouter      rx_request -> route -> tx_response
  |   [5] RtpForwarder       rx_dgram_in -> lookup stream -> forward
  |   [6] DataListener       gRPC DataService.Listen (CDC events)
  |
  +-- select! {              # FAIL-FAST: first task to complete wins
  |     h1 = stream_reader   => first_result = h1,
  |     h2 = stream_writer   => first_result = h2,
  |     h3 = datagram        => first_result = h3,
  |     h4 = router          => first_result = h4,
  |     h5 = rtp_forwarder   => first_result = h5,
  |     h6 = data_listener   => first_result = h6,
  |   }
  |
  +-- cancel_token.cancel()  # Signal ALL other tasks to stop
  +-- await remaining tasks  # Collect results, log errors
  +-- cleanup()              # Remove session from manager, close conn
```

**Cancellation flow:**
```
StreamReader exits (client disconnect)
  |
  +-- defer! { cancel_token.cancel() }     # StreamReader always cancels
  |
  +----> StreamWriter sees cancel -> break -> finish_stream()
  +----> DatagramHandler sees cancel -> break
  +----> RequestRouter sees cancel -> break
  +----> RtpForwarder sees cancel -> break
  +----> DataListener sees cancel -> break
```

### Request Processing Pipeline

```
                          QUIC RecvStream
                               |
                    +----------v----------+
                    |    StreamReader      |
                    | read varint length  |
                    | read N bytes        |
                    | decode StreamRequest|
                    +----------+----------+
                               |
                         kanal channel
                               |
                    +----------v----------+
                    |   RequestRouter     |
                    | match service {     |
                    |   Message => ...    |
                    |   Auth => ...       |
                    |   Network => ...    |
                    |   Token => ...      |
                    |   Data => ...       |
                    |   Session => ...    |
                    |   Profile => ...    |
                    | }                   |
                    +----------+----------+
                               |
                         kanal channel
                               |
                    +----------v----------+
                    |    StreamWriter     |
                    | encode_length_      |
                    |   delimited()       |
                    | send.write_all()    |
                    | (finish on exit)    |
                    +----------+----------+
                               |
                          QUIC SendStream
```

**Service routing tree** (routing/router.rs):
```
route_request(StreamRequest)
  |
  +-- MessageService
  |     +-- Send: start, stop, cancel, ping, rtp, speech_text
  |     +-- Receive: (incoming messages)
  |
  +-- AuthService
  |     +-- Login (Sign In with Apple)
  |     +-- RefreshToken
  |
  +-- NetworkService
  |     +-- Ping (latency measurement)
  |     +-- Stats (connection statistics)
  |
  +-- TokenService
  |     +-- Add (register push token)
  |
  +-- DataService
  |     +-- Listen (CDC event stream)
  |     +-- Send (client data push)
  |
  +-- SessionService
  |     +-- SetForeground (app lifecycle)
  |
  +-- ProfileService
        +-- Update, Get
```

### Datagram (RTP Audio) Pipeline

```
  Client                    Server
    |                         |
    |== QUIC DATAGRAM =======>|
    | [stream_id:4B][rtp:NB]  |
    |                         |
    |                    DatagramHandler
    |                    read_datagram()
    |                         |
    |                    kanal channel
    |                         |
    |                    RtpForwarder
    |                    parse [stream_id][rtp]
    |                    lookup SendStream by id
    |                    forward to subscribers
    |                         |
    |                    (reverse: subscriber sends)
    |                    kanal channel
    |                         |
    |                    DatagramHandler
    |                    send_datagram()
    |                         |
    |<== QUIC DATAGRAM =======|
```

## File Map

```
tolki-server-api/src/
  |
  +-- main.rs                          # Entry point, startup sequence
  +-- lib.rs                           # Public exports
  |
  +-- core/
  |     +-- config.rs                  # AppConfig (clap + env vars)
  |     +-- state.rs                   # AppState (Arc shared state)
  |     +-- error.rs                   # Error enum (Network, Auth, Internal)
  |
  +-- transport/                       # QUIC transport layer
  |     +-- server.rs                  # TquicEndpoint, accept loop
  |     +-- connection.rs              # Handshake, read_exact, session start
  |     +-- tls.rs                     # BoringSSL TLS config, certs
  |
  +-- session/                         # Per-connection session
  |     +-- session.rs                 # Session lifecycle, task supervision
  |     +-- config.rs                  # SessionConfig, SessionLimits
  |     +-- channels.rs               # kanal channel pairs
  |     +-- shared.rs                  # SessionShared (Arc mutable state)
  |     +-- stream_reader.rs           # RecvStream -> StreamRequest
  |     +-- stream_writer.rs           # StreamResponse -> SendStream
  |     +-- datagram.rs                # QUIC datagrams (RTP)
  |     +-- rtp_forwarder.rs           # Parse RTP, route to streams
  |     +-- send_streams.rs            # Active send stream registry
  |     +-- receive_streams.rs         # Active receive stream registry
  |     +-- data_listener.rs           # gRPC CDC listener
  |     +-- accumulator.rs             # Text accumulator for STT
  |     +-- manager.rs                 # Global session manager (DashMap)
  |
  +-- routing/                         # Request routing
  |     +-- router.rs                  # Service -> Method dispatch
  |     +-- response.rs                # StreamResponse builder
  |     +-- health.rs                  # HTTP health endpoint (axum)
  |     +-- handlers/
  |           +-- auth.rs              # Sign in, refresh token
  |           +-- message.rs           # Send/receive voice messages
  |           +-- network.rs           # Ping, stats
  |           +-- token.rs             # Push token registration
  |           +-- data.rs              # CDC data sync
  |           +-- session.rs           # App lifecycle
  |           +-- profile.rs           # User profile
  |           +-- refresh_limiter.rs   # Token refresh rate limit
  |
  +-- auth/                            # Authentication
  |     +-- mod.rs                     # authenticate_from_handshake()
  |     +-- token.rs                   # JWT validation
  |
  +-- backend/                         # gRPC backend connections
  |     +-- connection.rs              # DbConnection to tolki-server-db
  |     +-- locator.rs                 # Service discovery
  |     +-- pool.rs                    # Connection pooling
  |
  +-- proto/                           # Generated protobuf types
  |     +-- tolki.stream.v1.rs         # StreamRequest, StreamResponse
  |     +-- tolki.connection.v1.rs     # ConnectionHandshake
  |     +-- tolki.message.v1.rs        # Message types
  |     +-- tolki.auth.v1.rs           # Auth types
  |     +-- ...
  |
  +-- metrics.rs                       # Prometheus counters
```

## Key Types

| Type | File | Purpose |
|------|------|---------|
| `TquicEndpoint` | tquic/tokio_adapter | QUIC server/client endpoint |
| `TquicConnection` | tquic/tokio_adapter | Send-safe connection handle |
| `SendStream` | tquic/tokio_adapter | Async write half of QUIC stream |
| `RecvStream` | tquic/tokio_adapter | Async read half of QUIC stream |
| `AppState` | core/state.rs | Shared server state (Arc) |
| `Session` | session/session.rs | Per-connection session lifecycle |
| `StreamReader` | session/stream_reader.rs | Proto decoder from RecvStream |
| `StreamWriter` | session/stream_writer.rs | Proto encoder to SendStream |
| `DatagramHandler` | session/datagram.rs | RTP datagram I/O |
| `RtpForwarder` | session/rtp_forwarder.rs | RTP packet routing |
| `RequestRouter` | routing/router.rs | Service/method dispatch |
| `CancellationToken` | tokio_util | Per-session shutdown signal |

## tquic Async Model

tquic types (`Connection`, `Stream`) are `!Send` (use `Rc<RefCell<>>`).
The tokio adapter solves this with a dedicated driver thread:

```
+-----------------------------------------------+
|  Your code (any tokio task, Send)              |
|                                                |
|  TquicConnection, SendStream, RecvStream       |
|  (Send-safe handles with channels inside)      |
+---------------------+-------------------------+
                      |  ConnCmd, StreamCmd
                      |  (mpsc channels)
                      v
+-----------------------------------------------+
|  Driver thread (LocalSet, !Send)               |
|                                                |
|  loop {                                        |
|    poll commands from channels                 |
|    call tquic conn.stream_send/recv/etc        |
|    send results back via oneshot               |
|    tquic endpoint.process_connections()        |
|    sleep(min(timeout, 100ms))                  |
|  }                                             |
|                                                |
|  TransportHandler callbacks:                   |
|    on_conn_established -> notify established   |
|    on_stream_created -> send via mpsc          |
|    on_stream_readable -> notify readable       |
|    on_stream_writable -> notify writable       |
|    on_dgram_readable -> notify dgram_readable  |
|    on_conn_closed -> send via watch            |
+-----------------------------------------------+
```

## Message Wire Format

All stream messages use **length-delimited protobuf**:

```
StreamReader (varint-delimited):
  [varint length][StreamRequest protobuf]

Handshake (fixed 4-byte BE):
  [4 bytes BE u32 length][ConnectionHandshake protobuf]
```

Datagrams use **raw binary with stream ID prefix**:

```
QUIC DATAGRAM payload:
  [4 bytes BE stream_id][RTP packet bytes]
```
