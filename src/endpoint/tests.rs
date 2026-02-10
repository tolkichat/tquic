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

use super::*;
use crate::connection;
use crate::Config;
use crate::CongestionControlAlgorithm;
use crate::Error;
use crate::TlsConfig;
use bytes::Buf;
use connection::tests::TestPair as TestTool;
use mio;
use rand::prelude::SliceRandom;
use rand::rngs::mock::StepRng;
use rand::RngCore;
use ring::aead;
use ring::aead::LessSafeKey;
use ring::aead::UnboundKey;
use std::cmp;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::thread;
use std::thread::JoinHandle;
use std::time::Duration;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

struct TestPair {
    stop: Arc<AtomicBool>,
}

impl TestPair {
    fn new() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Run client/server endpoint in two threads.
    fn run(&mut self, cli_conf: Config, srv_conf: Config, case_conf: CaseConf) -> Result<()> {
        self.run_with_packet_filter(
            cli_conf,
            srv_conf,
            case_conf,
            Box::new(NoopPacketFilter {}),
        )
    }

    /// Run client/server endpoint in two threads.
    fn run_with_packet_filter(
        &mut self,
        cli_conf: Config,
        srv_conf: Config,
        case_conf: CaseConf,
        cli_filter: Box<dyn PacketFilter + Send>,
    ) -> Result<()> {
        // Exit if client/server thread panic
        std::panic::set_hook(Box::new(|panic_info| {
            println!(
                "unexpected panic {:?} occurred in {:?} and exit",
                panic_info.payload().downcast_ref::<&str>(),
                panic_info.location()
            );
            std::process::exit(-1);
        }));

        // Prepare client/server sockets and config
        let mut cli_poll = mio::Poll::new().unwrap();
        let mut cli_sock =
            TestSocket::new(cli_poll.registry(), &case_conf, "CLIENT".into()).unwrap();
        cli_sock.set_filter(cli_filter);
        let cli_addr = cli_sock.local_addr()?;
        let cli_case_conf = case_conf.clone();
        let cli_stop = Arc::clone(&self.stop);

        let mut srv_poll = mio::Poll::new().unwrap();
        let srv_sock =
            TestSocket::new(srv_poll.registry(), &case_conf, "SERVER".into()).unwrap();
        let srv_addr = srv_sock.local_addr()?;
        let srv_case_conf = case_conf.clone();
        let srv_stop = Arc::clone(&self.stop);

        let host = Some("example.org");
        let session = cli_case_conf.session.clone();
        let token = cli_case_conf.token.clone();

        // Create and run client endpoint in child thread
        let client = thread::spawn(move || {
            let session = session.as_ref().map(Vec::as_ref);
            let token = token.as_ref().map(Vec::as_ref);

            let cli_hdl = Box::new(ClientHandler::new(cli_case_conf, Arc::clone(&cli_stop)));
            let cli_sock = Rc::new(cli_sock);
            let mut endpoint =
                Endpoint::new(Box::new(cli_conf), false, cli_hdl, cli_sock.clone());

            endpoint
                .connect(cli_addr, srv_addr, host, session, token, None)
                .unwrap();
            endpoint.process_connections().unwrap();
            TestPair::event_loop(&mut endpoint, &mut cli_poll, &cli_sock, &cli_stop).unwrap();
        });

        // Create and run server endpoint in child thread
        let server = thread::spawn(move || {
            let srv_hdl = Box::new(ServerHandler::new(srv_case_conf, Arc::clone(&srv_stop)));
            let srv_sock = Rc::new(srv_sock);

            let mut endpoint =
                Endpoint::new(Box::new(srv_conf), true, srv_hdl, srv_sock.clone());
            TestPair::event_loop(&mut endpoint, &mut srv_poll, &srv_sock, &srv_stop).unwrap();
        });

        client.join().unwrap();
        server.join().unwrap();
        Ok(())
    }

    /// Run client/server endpoint with default config.
    fn run_with_test_config(&mut self, case_conf: CaseConf) -> Result<()> {
        let mut cli_conf = TestPair::new_test_config(false)?;
        cli_conf.set_congestion_control_algorithm(case_conf.cc_algor);
        let mut srv_conf = TestPair::new_test_config(true)?;
        srv_conf.set_congestion_control_algorithm(case_conf.cc_algor);

        self.run(cli_conf, srv_conf, case_conf)
    }

    /// Run event loop for the endpoint.
    fn event_loop(
        e: &mut Endpoint,
        poll: &mut mio::Poll,
        sock: &TestSocket,
        stop: &Arc<AtomicBool>,
    ) -> Result<()> {
        let mut events = mio::Events::with_capacity(1024);

        while !stop.load(Ordering::Relaxed) {
            // Wait for timeout/IO events.
            let timeout = match e.timeout() {
                Some(v) => cmp::max(Some(v), Some(crate::TIMER_GRANULARITY)),
                // Always allow the test thread to wake up and check for stop status.
                None => {
                    trace!("{} event loop: no expirable connection.", e.trace_id());
                    Some(crate::TIMER_GRANULARITY * 100)
                }
            };

            trace!(
                "{} event loop: poll events (timeout: {:?})...",
                e.trace_id(),
                timeout.unwrap(),
            );
            poll.poll(&mut events, timeout)?;

            // Process timeout events
            if events.is_empty() {
                trace!("{} event loop: process timeout events", e.trace_id());
                e.on_timeout(Instant::now());
                if let Err(err) = e.process_connections() {
                    trace!(
                        "{} event loop: process_connections(): {:?}",
                        e.trace_id(),
                        err
                    );
                }
                continue;
            }

            // Process IO events
            for event in events.iter() {
                trace!("{} event loop: process io events", e.trace_id());
                if event.is_readable() {
                    TestPair::process_read_event(e, sock)?;
                }
            }
            if let Err(err) = e.process_connections() {
                trace!(
                    "{} event loop: process_connections(): {:?}",
                    e.trace_id(),
                    err
                );
            }
        }

        trace!("{} event loop exit", e.trace_id());
        Ok(())
    }

    // Process read event on the socket.
    fn process_read_event(e: &mut Endpoint, s: &TestSocket) -> Result<()> {
        let mut recv_buf = vec![0; 65535];
        loop {
            // Read datagram from the socket.
            let (len, remote) = match s.socket.recv_from(&mut recv_buf) {
                Ok(v) => v,
                Err(err) => {
                    if err.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("{} socket recv would block, stop recving", e.trace_id());
                        break;
                    }
                    return Err(format!("socket recv error: {:?}", err).into());
                }
            };

            // Process the incoming packet.
            let pkt_buf = &mut recv_buf[..len];
            let pkt_info = PacketInfo {
                src: remote,
                dst: s.socket.local_addr().unwrap(),
                time: Instant::now(),
            };
            match e.recv(pkt_buf, &pkt_info) {
                Ok(_) => {}
                Err(err) => {
                    error!("{} recv failed: {:?}, drop the packet", e.trace_id, err);
                    continue;
                }
            };
        }
        Ok(())
    }

    /// Create a resume address token.
    fn new_test_address_token(client_ip: IpAddr, key: &[u8]) -> Vec<u8> {
        let client_addr = SocketAddr::new(client_ip, 0);
        let token = AddressToken::new_resume_token(client_addr);

        let token_key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &key).unwrap());
        token.encode(&token_key).unwrap()
    }

    /// Create test config for endpoint
    fn new_test_config(is_server: bool) -> Result<Config> {
        let mut conf = Config::new()?;
        conf.set_initial_max_data(1024 * 1024 * 10);
        conf.set_initial_max_stream_data_bidi_local(1024 * 1024 * 1);
        conf.set_initial_max_stream_data_bidi_remote(1024 * 1024 * 1);
        conf.set_initial_max_stream_data_uni(1024 * 1024 * 1);
        conf.set_initial_max_streams_bidi(100);
        conf.set_initial_max_streams_uni(100);
        conf.set_max_idle_timeout(10000);
        conf.set_max_handshake_timeout(5000);
        conf.set_recv_udp_payload_size(1500);
        conf.set_max_connection_window(1024 * 1024 * 10);
        conf.set_max_stream_window(1024 * 1024 * 1);
        conf.set_max_concurrent_conns(100);
        conf.set_active_connection_id_limit(4);
        conf.set_ack_delay_exponent(3);
        conf.set_max_ack_delay(25);
        conf.set_reset_token_key([1u8; 64]);
        conf.set_send_batch_size(16);
        conf.set_initial_rtt(33); // for reducing test case execution time
        conf.set_max_handshake_timeout(0);

        let application_protos = vec![b"h3".to_vec()];
        let tls_config = if !is_server {
            TlsConfig::new_client_config(application_protos, true)?
        } else {
            let mut tls_config = TlsConfig::new_server_config(
                "src/tls/testdata/cert.crt",
                "src/tls/testdata/cert.key",
                application_protos,
                true,
            )?;
            tls_config.set_ticket_key(&vec![0x73; 48])?;
            tls_config
        };
        conf.set_tls_config(tls_config);

        Ok(conf)
    }

    /// Create test session data using default ticket key
    pub fn new_test_session_state() -> Vec<u8> {
        let mut client_config = TestPair::new_test_config(false).unwrap();
        let mut server_config = TestPair::new_test_config(true).unwrap();

        let mut test_pair =
            connection::tests::TestPair::new(&mut client_config, &mut server_config).unwrap();
        test_pair.handshake().unwrap();
        let session = test_pair.client.session().unwrap();

        trace!(
            "Extract session state for resumed handshake: {} bytes",
            session.len()
        );
        session.to_vec()
    }
}

struct TestSocketState {
    /// Rng for testing purposes.
    rng: StepRng,

    /// Packet filter for outgoing packets
    filter: Option<Box<dyn PacketFilter + Send>>,
}

/// UdpSocket with fault injection.
struct TestSocket {
    socket: mio::net::UdpSocket,

    state: RefCell<TestSocketState>,

    /// Used for simulating packet loss (0~100)
    packet_loss: u32,

    /// Used for simulating one way delay (ms)
    packet_delay: u32,

    /// Used for simulating out-of-order packet (0~100)
    packet_reorder: u32,

    /// Used for simulating duplicated packet (0~100)
    packet_duplication: u32,

    /// Used for simulating corrupted packet (0~100)
    packet_corruption: u32,

    /// Unique trace id
    trace_id: String,
}

impl TestSocket {
    /// Create a UdpSocket using random unused port.
    fn new(reg: &mio::Registry, conf: &CaseConf, trace_id: String) -> Result<Self> {
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut socket = mio::net::UdpSocket::bind(addr)?;

        const TOKEN: mio::Token = mio::Token(0);
        reg.register(&mut socket, TOKEN, mio::Interest::READABLE)
            .unwrap();

        let state = RefCell::new(TestSocketState {
            rng: StepRng::new(0, 1),
            filter: None,
        });

        Ok(Self {
            socket,
            state,
            packet_loss: conf.packet_loss,
            packet_delay: conf.packet_delay,
            packet_reorder: conf.packet_reorder,
            packet_duplication: conf.packet_duplication,
            packet_corruption: conf.packet_corruption,
            trace_id,
        })
    }

    /// Set the customized packter filter
    fn set_filter(&mut self, filter: Box<dyn PacketFilter + Send>) {
        self.state.borrow_mut().filter = Some(filter);
    }

    /// Return the local socket address.
    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Whether an abnormal event should be injected.
    fn sampling(&self, rate: u32) -> bool {
        self.state.borrow_mut().rng.next_u32() % 100 < rate
    }

    /// Filter packets which are delayed long enough.
    fn try_delay_packets(
        &self,
        mut pkts: Vec<(Vec<u8>, PacketInfo)>,
    ) -> Vec<(Vec<u8>, PacketInfo)> {
        if self.packet_delay == 0 {
            return pkts;
        }

        let now = Instant::now();
        let delay = Duration::from_millis(self.packet_delay as u64);
        let count = pkts.len();
        for i in 0..count {
            let (_, info) = pkts[i];
            match now.checked_duration_since(info.time) {
                None => {
                    pkts.truncate(i);
                    break;
                }
                Some(v) if v < delay => {
                    pkts.truncate(i);
                    break;
                }
                _ => (),
            }
        }

        trace!(
            "{} {} out of {} packets is DELAYED !",
            &self.trace_id,
            count - pkts.len(),
            count
        );
        pkts
    }

    /// Randomly reorder packets.
    fn try_reorder_packets(&self, pkts: &mut [(Vec<u8>, PacketInfo)], window: usize) {
        if self.packet_reorder == 0 || !self.sampling(self.packet_reorder) {
            return;
        }

        let mut start = 0;
        while start < pkts.len() {
            let end = cmp::min(start + window, pkts.len());
            let range = &mut pkts[start..end];
            range.shuffle(&mut self.state.borrow_mut().rng);
            start = end;
        }
        trace!(
            "{} {} packets REORDERD ! reorder threshold: {}",
            &self.trace_id,
            pkts.len(),
            window,
        );
    }

    // Whether the packet should be dropped.
    fn try_drop_packet(&self, pkt: &[u8], info: &PacketInfo) -> bool {
        if self.packet_loss == 0 || !self.sampling(self.packet_loss) {
            return false;
        }

        trace!(
            "{} write {} bytes {:?} but it is LOST !",
            &self.trace_id,
            pkt.len(),
            info,
        );
        true
    }

    /// Randomly change one byte of the packet data.
    fn try_mangle_packet(&self, pkt: &mut [u8], info: &PacketInfo) {
        if self.packet_corruption == 0 || !self.sampling(self.packet_corruption) {
            return;
        }

        let idx = (rand::random::<u32>() as usize) % pkt.len();
        let val = rand::random::<u8>();
        pkt[idx as usize] = val;
        trace!(
            "{} write {} bytes {:?} but it is CORRUPTED !",
            &self.trace_id,
            pkt.len(),
            info,
        );
    }

    /// Randomly dupulicate the packet.
    fn try_dup_packet(&self, pkt: &[u8], info: &PacketInfo) {
        if self.packet_duplication == 0 || !self.sampling(self.packet_duplication) {
            return;
        }

        let _ = self.socket.send_to(pkt, info.dst);
        trace!(
            "{} write {} bytes {:?} but it is DUPLICATED !",
            &self.trace_id,
            pkt.len(),
            info,
        );
    }
}

impl PacketSendHandler for TestSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> crate::Result<usize> {
        let mut count = 0;

        let mut pkts = pkts.to_vec();
        if let Some(ref mut f) = &mut self.state.borrow_mut().filter {
            f.filter(&mut pkts);
        }

        // Simulate event of packet delay
        pkts = self.try_delay_packets(pkts);
        if pkts.is_empty() {
            return Ok(0);
        }

        // Simulate event of packet reorder
        self.try_reorder_packets(&mut pkts, 4);

        for (mut pkt, info) in pkts {
            // Simulate event of packet loss
            if self.try_drop_packet(&pkt, &info) {
                count += 1;
                continue;
            }

            // Simulate event of packet corruption
            self.try_mangle_packet(&mut pkt, &info);

            // Send the packet out.
            if let Err(e) = self.socket.send_to(&pkt, info.dst) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    return Ok(count);
                }
                return Err(crate::Error::InvalidOperation(
                    format!("send_to(): {:?}", e).into(),
                ));
            }
            trace!("{} write {} bytes {:?}", &self.trace_id, pkt.len(), info);
            count += 1;

            // Simulate event of packet duplication
            self.try_dup_packet(&pkt, &info);
        }

        Ok(count)
    }
}

trait PacketFilter {
    fn filter(&mut self, pkts: &mut Vec<(Vec<u8>, PacketInfo)>);
}

struct NoopPacketFilter {}

impl PacketFilter for NoopPacketFilter {
    fn filter(&mut self, _pkts: &mut Vec<(Vec<u8>, PacketInfo)>) {}
}

struct FirstPacketFilter {
    count: u64,
    drop_or_disorder: bool,
}

impl FirstPacketFilter {
    fn new(drop_or_disorder: bool) -> Self {
        Self {
            count: 0,
            drop_or_disorder,
        }
    }
}

impl PacketFilter for FirstPacketFilter {
    fn filter(&mut self, pkts: &mut Vec<(Vec<u8>, PacketInfo)>) {
        if self.count == 0 {
            if self.drop_or_disorder && pkts.len() >= 1 {
                pkts.remove(0);
            } else if pkts.len() >= 2 {
                pkts.swap(0, 1);
            }
        }
        self.count += pkts.len() as u64;
    }
}

// A mocked socket which implements PacketSendHandler.
struct MockSocket {
    packets: RefCell<Vec<(Vec<u8>, PacketInfo)>>,
}

impl MockSocket {
    fn new() -> Self {
        MockSocket {
            packets: RefCell::new(Vec::new()),
        }
    }

    // Delivery the outgoing packets to the target endpoint
    fn transfer(&self, e: &mut Endpoint) -> Result<usize> {
        let count = self.packets.borrow().len();
        let mut packets = self.packets.borrow_mut();
        for (pkt, info) in packets.iter_mut() {
            e.recv(pkt, info)?;
        }
        packets.clear();
        Ok(count)
    }
}

impl PacketSendHandler for MockSocket {
    fn on_packets_send(&self, pkts: &[(Vec<u8>, PacketInfo)]) -> crate::Result<usize> {
        let mut packets = self.packets.borrow_mut();
        packets.extend_from_slice(pkts);
        Ok(pkts.len())
    }
}

#[derive(Clone, Default)]
struct CaseConf {
    handshake_only: bool,
    client_0rtt_expected: bool,
    resumption_expected: bool,
    new_token_expected: bool,
    session: Option<Vec<u8>>,
    token: Option<Vec<u8>>,
    request_num: u32,
    request_size: usize,
    cc_algor: CongestionControlAlgorithm,
    packet_loss: u32,
    packet_delay: u32,
    packet_reorder: u32,
    packet_duplication: u32,
    packet_corruption: u32,
}

#[derive(Default)]
struct ClientHandler {
    data: Vec<u8>,
    reqs: Vec<bytes::Bytes>,
    rsps: Vec<bytes::BytesMut>,
    count: u16,
    conf: CaseConf,
    token: Option<Vec<u8>>,
    stop: Arc<AtomicBool>,
}

impl ClientHandler {
    fn new(conf: CaseConf, stop: Arc<AtomicBool>) -> Self {
        let len = conf.request_size * (conf.request_num as usize);
        let mut handler = Self {
            data: vec![0; len],
            reqs: Vec::new(),
            rsps: Vec::new(),
            count: 0,
            conf,
            token: None,
            stop,
        };
        rand::thread_rng().fill_bytes(&mut handler.data);

        for i in 0..handler.conf.request_num {
            let start = (i as usize) * handler.conf.request_size;
            let buf = &handler.data[start..start + handler.conf.request_size];
            handler.reqs.push(bytes::Bytes::copy_from_slice(buf));
            handler.rsps.push(bytes::BytesMut::new());
        }
        handler
    }

    fn write_request(&mut self, conn: &mut Connection, req_id: usize) {
        let stream_id = (req_id * 4) as u64;
        let cap = conn.stream_capacity(stream_id).unwrap();
        let len = cmp::min(self.reqs[req_id].len(), cap);

        let buf = self.reqs[req_id].split_to(len);
        let fin = self.reqs[req_id].is_empty();
        conn.stream_write(stream_id, buf, fin).unwrap();
    }
}

impl TransportHandler for ClientHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        assert_eq!(conn.is_in_early_data(), self.conf.client_0rtt_expected);
        trace!("{} connection created", conn.trace_id());

        // Try to send requests to the server (0RTT)
        if self.conf.client_0rtt_expected {
            for i in 0..self.reqs.len() {
                let stream_id = (i * 4) as u64;
                conn.stream_set_priority(stream_id, 1, false).unwrap();
                self.write_request(conn, i);
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        trace!("{} connection established", conn.trace_id());
        assert_eq!(conn.is_resumed(), self.conf.resumption_expected);

        // Try to send requests to the server (1RTT)
        for i in 0..self.reqs.len() {
            let stream_id = (i * 4) as u64;
            conn.stream_set_priority(stream_id, 1, false).unwrap();
            self.write_request(conn, i);
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        trace!("{} connection closed", conn.trace_id());
        assert_eq!(conn.stream_iter().count(), 0);
        if self.conf.new_token_expected {
            assert!(self.token.is_some());
        }
        self.stop.store(true, Ordering::Relaxed);
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        trace!("{} stream {} created", conn.trace_id(), stream_id);
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let idx = (stream_id / 4) as usize;
        let mut buf = vec![0; 2048];

        // Read response from the server
        let (len, fin) = conn.stream_read(stream_id, &mut buf).unwrap();
        self.rsps[idx].extend_from_slice(&mut buf[..len]);

        // Validate the response
        if fin {
            self.count += 1;
            let len = self.rsps[idx].len();
            let buf = self.rsps[idx].split_to(len);
            let buf = buf.freeze();

            let start = idx * (self.conf.request_size) as usize;
            let raw = &self.data[start..start + self.conf.request_size];
            assert_eq!(raw, &buf);
        }

        // Close connection when all requests has been processed
        if self.count as usize == self.reqs.len() {
            conn.close(true, 0, &[]).unwrap();
            trace!("client close connection");
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let i = (stream_id / 4) as usize;
        self.write_request(conn, i);
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        trace!("{} stream {} closed", conn.trace_id(), stream_id);
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {
        self.token = Some(token);
    }
}

struct ServerStreamContext {
    buf: bytes::BytesMut,
    fin: bool,
}

struct ServerHandler {
    handshake_only: bool,
    stop: Arc<AtomicBool>,
}

impl ServerHandler {
    fn new(conf: CaseConf, stop: Arc<AtomicBool>) -> Self {
        Self {
            handshake_only: conf.handshake_only,
            stop,
        }
    }
}

impl TransportHandler for ServerHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        trace!("{} connection created", conn.trace_id());
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        trace!("{} connection established", conn.trace_id());
        if self.handshake_only {
            conn.close(true, 0, &[]).unwrap();
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        trace!("{} connection closed", conn.trace_id());
        assert_eq!(conn.stream_iter().count(), 0);
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        let sctx = ServerStreamContext {
            buf: bytes::BytesMut::new(),
            fin: false,
        };
        conn.stream_set_context(stream_id, sctx).unwrap();
    }

    // Read stream data and add to buffer.
    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        let mut buf = vec![0; 2048];
        let (len, fin) = conn.stream_read(stream_id, &mut buf).unwrap();

        let sctx = conn.stream_context(stream_id).unwrap();
        let sctx = sctx.downcast_mut::<ServerStreamContext>().unwrap();
        sctx.buf.extend_from_slice(&mut buf[..len]);
        sctx.fin = fin;
    }

    // Echo data received from the client.
    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        let cap = conn.stream_capacity(stream_id).unwrap();

        // Prepare send buffer
        let sctx = conn.stream_context(stream_id).unwrap();
        let sctx = sctx.downcast_mut::<ServerStreamContext>().unwrap();
        if sctx.buf.is_empty() {
            return;
        }
        let len = cmp::min(cap, sctx.buf.len());
        let buf = sctx.buf.split_to(len);
        let buf = buf.freeze();

        // Send data to the client
        let fin = sctx.fin && sctx.buf.is_empty();
        conn.stream_write(stream_id, buf, fin).unwrap();
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        trace!("{} stream {} closed", conn.trace_id(), stream_id);
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {}
}

// Test Initial packet
const TEST_INITIAL: [u8; 700] = [
    0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00,
    0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
    0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d, 0x92,
    0xec, 0x35, 0x6c, 0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd, 0x44, 0x9f, 0x63, 0x30,
    0x00, 0x99, 0xf3, 0x99, 0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3, 0x1f, 0x84, 0x29,
    0x15, 0x7b, 0xb3, 0x5a, 0x12, 0x82, 0xa6, 0x43, 0xa8, 0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50,
    0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c, 0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed,
    0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1, 0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6,
    0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12, 0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43,
    0xfa, 0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89, 0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0,
    0x22, 0x52, 0x15, 0x5e, 0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5, 0x45, 0x7a, 0xfd, 0x84, 0xd0,
    0x5d, 0xff, 0xfd, 0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15, 0x46, 0x82, 0xe9, 0xcf,
    0x01, 0x2f, 0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08, 0x4d, 0xce, 0x25,
    0xff, 0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3, 0x62, 0xc2,
    0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec, 0x4e,
    0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e,
    0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba, 0xd1, 0xdb, 0x4b,
    0xa3, 0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6,
    0xa8, 0xe5, 0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3, 0x0c, 0x5c, 0x42, 0x87, 0xe5,
    0x38, 0x05, 0xdb, 0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39,
    0xbe, 0x2e, 0x20, 0xd8, 0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae,
    0x05, 0x30, 0x60, 0xae, 0x6c, 0x7b, 0x43, 0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b,
    0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7, 0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6,
    0x81, 0xd5, 0x82, 0x36, 0x3a, 0xa5, 0xf8, 0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63,
    0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4, 0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b,
    0xa6, 0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56, 0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65,
    0x63, 0x6a, 0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74, 0x3e, 0xeb, 0x52, 0x4b, 0xe2,
    0x2b, 0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74, 0x68, 0x44, 0x9a, 0x13,
    0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7, 0xfe, 0x94, 0x2b,
    0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a, 0xc6, 0x98,
    0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a, 0x33,
    0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
    0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f, 0xe9, 0xc5, 0xd0, 0xb2, 0x3a,
    0x22, 0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81, 0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72,
    0x66, 0x32, 0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11, 0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f,
    0xeb, 0x3e, 0xdf, 0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d,
    0xbf, 0xe5, 0x89, 0x64, 0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf,
    0x4e, 0x25, 0x13, 0xe4, 0xf0, 0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06,
    0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd, 0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02,
    0xf9, 0x39, 0xb0, 0xe1, 0xab, 0xd5, 0x76, 0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c,
    0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff, 0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93,
    0x46, 0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2, 0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33,
    0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98, 0xe3, 0xfc, 0x43, 0x3f, 0x9f,
    0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f, 0x60, 0x47, 0x47, 0x2f,
    0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd, 0xc3, 0x24, 0x04,
    0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95, 0xde, 0x37, 0x25, 0x2d,
    0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10,
];

// Test stateless reset packet.
const TEST_STATELESS_RESET: [u8; 42] = [
    0x40, 0xc1, 0xe7, 0x9a, 0xb0, 0x94, 0xc7, 0xa2, 0x49, 0x43, 0x84, 0xbb, 0x23, 0x05, 0x6f,
    0x20, 0x11, 0x0f, 0x9b, 0x13, 0x01, 0x36, 0xf3, 0xa0, 0x45, 0xb8, 0x9f, 0x09, 0x36, 0x79,
    0x0f, 0xc2, 0x7f, 0x14, 0xed, 0x3d, 0x67, 0xbf, 0x79, 0x21, 0xad, 0xc7,
];

#[test]
fn handshake_full_with_retry_disabled() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn handshake_full_with_retry_enabled() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.enable_retry(true);

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_resume_with_retry_disabled() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_resume_with_retry_enabled() -> Result<()> {
    let mut t = TestPair::new();

    let token_key = [1; 16];
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 8, 8, 8));
    let token = TestPair::new_test_address_token(client_ip, &token_key);

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.enable_retry(true);

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.token = Some(token);
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_resume_with_invalid_session() -> Result<()> {
    let mut t = TestPair::new();

    let token_key = [1; 16];
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 7, 7, 7));
    let token = TestPair::new_test_address_token(client_ip, &token_key);

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.set_address_token_key(vec![token_key])?;
    let mut tls_config = TlsConfig::new_server_config(
        "src/tls/testdata/cert.crt",
        "src/tls/testdata/cert.key",
        vec![b"h3".to_vec()],
        true,
    )?;
    tls_config.set_ticket_key(&vec![0x01; 48])?;
    srv_conf.set_tls_config(tls_config);

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.token = Some(token);
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = false;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_resume_with_invalid_token() -> Result<()> {
    let mut t = TestPair::new();

    let token_key = [1; 16];
    let client_ip = IpAddr::V4(Ipv4Addr::new(127, 8, 8, 8));
    let token = TestPair::new_test_address_token(client_ip, &token_key);

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.set_address_token_key(vec![token_key])?;

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.token = Some(token);
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_client_zero_cid() -> Result<()> {
    let mut t = TestPair::new();

    let mut cli_conf = TestPair::new_test_config(false)?;
    cli_conf.set_cid_len(0);
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_server_zero_cid() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.set_cid_len(0);

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_both_zero_cid() -> Result<()> {
    let mut t = TestPair::new();

    let mut cli_conf = TestPair::new_test_config(false)?;
    cli_conf.set_cid_len(0);
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.set_cid_len(0);

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.packet_loss = 1;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_packet_delay() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.packet_delay = 20;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_packet_reorder() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.packet_reorder = 10;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_packet_corruption() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.packet_corruption = 1;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn handshake_with_packet_duplication() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.handshake_only = true;
    case_conf.packet_duplication = 2;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn endpoint_connect() -> Result<()> {
    let cli_addr: SocketAddr = "127.8.8.8:8888".parse().unwrap();
    let srv_addr: SocketAddr = "127.8.8.8:8443".parse().unwrap();
    let host = Some("example.org");

    // connect on client endpoint
    let mut e = Endpoint::new(
        Box::new(TestPair::new_test_config(false)?),
        false,
        Box::new(ClientHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        Rc::new(MockSocket::new()),
    );
    assert!(e
        .connect(cli_addr, srv_addr, host, None, None, None)
        .is_ok());
    assert_eq!(e.conns.len(), 1);

    // gracefully close client endpoint
    e.close(false);
    assert_eq!(e.conns.len(), 1);
    assert!(e
        .connect(cli_addr, srv_addr, host, None, None, None)
        .is_err());
    assert_eq!(e.conns.len(), 1);

    // forcibly close client endpoint
    e.close(true);
    assert_eq!(e.conns.len(), 0);

    // connect on server endpoint
    let mut e = Endpoint::new(
        Box::new(TestPair::new_test_config(true)?),
        true,
        Box::new(ServerHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        Rc::new(MockSocket::new()),
    );
    assert!(e
        .connect(cli_addr, srv_addr, host, None, None, None)
        .is_err());
    assert!(e.conns.is_empty());

    Ok(())
}

#[test]
fn endpoint_new_token() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.set_address_token_key(vec![[1; 16]])?;

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 100;
    case_conf.new_token_expected = true;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn endpoint_basic_operations() -> Result<()> {
    let mut e = Endpoint::new(
        Box::new(TestPair::new_test_config(false)?),
        false,
        Box::new(ClientHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        Rc::new(MockSocket::new()),
    );
    let id = "ClientEndpoint";
    e.set_trace_id(String::from(id));
    assert_eq!(e.trace_id(), id);
    assert_eq!(e.conn_exist(ConnectionId::random()), false);

    Ok(())
}

#[test]
fn endpoint_version_negtiation() -> Result<()> {
    let mut initial_unknown_ver = TEST_INITIAL.clone();
    initial_unknown_ver[1] = 0x73;

    let sock = Rc::new(MockSocket::new());
    let mut e = Endpoint::new(
        Box::new(TestPair::new_test_config(true)?),
        true,
        Box::new(ServerHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        sock.clone(),
    );
    let info = TestTool::new_test_packet_info(false);

    // Server recv an Initial with unknown version
    e.recv(&mut initial_unknown_ver, &info)?;
    e.process_connections()?;

    // Server send Version Negoiation
    let packets = sock.packets.borrow();
    assert!(packets.len() > 0);

    let (packet, _) = &packets[0];
    let (hdr, _) = PacketHeader::from_bytes(&packet, 8)?;
    assert_eq!(hdr.pkt_type, PacketType::VersionNegotiation);
    Ok(())
}

#[test]
fn endpoint_stateless_reset_for_restart() -> Result<()> {
    let new_endpoint = |is_server, conf, sock: Rc<MockSocket>| -> Endpoint {
        Endpoint::new(
            Box::new(conf),
            is_server,
            Box::new(ClientHandler::new(
                CaseConf::default(),
                Arc::new(AtomicBool::new(false)),
            )),
            sock.clone(),
        )
    };

    // client endpoint
    let mut client_conf = TestPair::new_test_config(false)?;
    client_conf.enable_stateless_reset(true);
    let client_sock = Rc::new(MockSocket::new());
    let mut client = new_endpoint(false, client_conf, client_sock.clone());

    // server endpoint
    let mut server_conf = TestPair::new_test_config(true)?;
    server_conf.enable_stateless_reset(true);
    server_conf.set_reset_token_key([1; 64]);
    let server_sock = Rc::new(MockSocket::new());
    let mut server = new_endpoint(true, server_conf, server_sock.clone());

    // create a connection
    let cli_addr: SocketAddr = "127.8.8.8:8888".parse().unwrap();
    let srv_addr: SocketAddr = "127.8.8.8:8443".parse().unwrap();
    let host = Some("example.org");
    let cli_conn = client.connect(cli_addr, srv_addr, host, None, None, None)?;
    client.process_connections()?;
    assert!(client_sock.transfer(&mut server)? > 0);
    server.process_connections()?;
    assert!(server_sock.transfer(&mut client)? > 0);
    assert_eq!(client.conns.len(), 1);
    assert_eq!(server.conns.len(), 1);

    // Fake restarting server after handshake
    client.process_connections()?;
    assert!(client_sock.transfer(&mut server)? > 0);
    server.process_connections()?;
    assert!(server_sock.transfer(&mut client)? > 0);
    server.close(true);

    let mut server_conf = TestPair::new_test_config(true)?;
    server_conf.enable_stateless_reset(true);
    server_conf.set_reset_token_key([1; 64]);
    let server_sock = Rc::new(MockSocket::new());
    let mut server = new_endpoint(true, server_conf, server_sock.clone());
    assert_eq!(client.conns.len(), 1);
    assert_eq!(server.conns.len(), 0);

    // Client send packets to server
    client.process_connections()?;
    assert!(client_sock.transfer(&mut server)? > 0);

    // Server send Stateless Reset
    server.process_connections()?;
    assert!(server_sock.transfer(&mut client)? > 0);

    // Client detect Stateless Reset
    client.process_connections()?;
    let cli_conn = client.conn_get_mut(cli_conn).unwrap();
    assert!(cli_conn.is_reset());

    Ok(())
}

#[test]
fn endpoint_stateless_reset_for_unknown_packet() -> Result<()> {
    let cases = vec![
        // is_server, enable_reset, packet, got_reset
        (false, true, Vec::from(TEST_INITIAL), true),
        (false, false, Vec::from(TEST_INITIAL), false),
        (false, true, Vec::from(TEST_STATELESS_RESET), true),
        (false, false, Vec::from(TEST_STATELESS_RESET), false),
        (true, true, Vec::from(TEST_INITIAL), false),
        (true, false, Vec::from(TEST_INITIAL), false),
        (true, true, Vec::from(TEST_STATELESS_RESET), true),
        (true, false, Vec::from(TEST_STATELESS_RESET), false),
    ];

    for (is_server, enable_reset, pkt, got_reset) in cases {
        let mut conf = TestPair::new_test_config(is_server)?;
        conf.enable_stateless_reset(enable_reset);
        let sock = Rc::new(MockSocket::new());
        let mut e = Endpoint::new(
            Box::new(conf),
            is_server,
            Box::new(ServerHandler::new(
                CaseConf::default(),
                Arc::new(AtomicBool::new(false)),
            )),
            sock.clone(),
        );

        // Endpoint recv an unknown packet.
        let mut pkt_unknown = pkt.clone();
        let info = TestTool::new_test_packet_info(is_server);
        e.recv(&mut pkt_unknown, &info)?;

        // Endpoint send stateless reset
        e.process_connections()?;
        let packets = sock.packets.borrow();
        if got_reset {
            assert!(packets.len() > 0);
            let (packet, _) = &packets[0];
            let (hdr, _) = PacketHeader::from_bytes(&packet, 8)?;
            assert_eq!(hdr.pkt_type, PacketType::OneRTT);
        } else {
            assert!(packets.len() == 0);
        }
    }

    Ok(())
}

#[test]
fn endpoint_client_recv_invalid_initial() -> Result<()> {
    let sock = Rc::new(MockSocket::new());
    let mut conf = TestPair::new_test_config(false)?;
    conf.enable_stateless_reset(false);

    let mut e = Endpoint::new(
        Box::new(conf),
        false,
        Box::new(ClientHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        sock.clone(),
    );
    let info = TestTool::new_test_packet_info(false);

    // Client recv an Initial with ClientHello message
    let mut initial = TEST_INITIAL.clone();
    e.recv(&mut initial, &info)?;
    assert_eq!(e.conns.len(), 0);

    Ok(())
}

#[test]
fn endpoint_conn_raw_pointer_stability() -> Result<()> {
    let cli_addr: SocketAddr = "127.8.8.8:8888".parse().unwrap();
    let srv_addr: SocketAddr = "127.8.8.8:8443".parse().unwrap();
    let host = Some("example.org");
    let mut e = Endpoint::new(
        Box::new(TestPair::new_test_config(false)?),
        false,
        Box::new(ClientHandler::new(
            CaseConf::default(),
            Arc::new(AtomicBool::new(false)),
        )),
        Rc::new(MockSocket::new()),
    );

    // Insert connection 0
    assert!(e
        .connect(cli_addr, srv_addr, host, None, None, None)
        .is_ok());
    assert_eq!(e.conns.len(), 1);
    let raw_ptr = e.conn_get_mut(0).unwrap() as *const Connection;

    // Insert more connections and cause reallocation
    let capacity = e.conns.conns.capacity();
    for i in 0..capacity {
        assert!(e
            .connect(cli_addr, srv_addr, host, None, None, None)
            .is_ok());
    }
    assert_ne!(e.conns.conns.capacity(), capacity);

    // Check raw pointer of connection 0
    let raw_ptr2 = e.conn_get_mut(0).unwrap() as *const Connection;
    assert_eq!(raw_ptr, raw_ptr2);

    Ok(())
}

#[test]
fn transfer_single_stream_1rtt() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_0rtt_and_1rtt() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_0rtt_with_initial_lost() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    // Drop the first packet(Initial) sent by the client
    let filter = Box::new(FirstPacketFilter::new(true));
    t.run_with_packet_filter(cli_conf, srv_conf, case_conf, filter)?;
    Ok(())
}

#[test]
fn transfer_single_stream_0rtt_with_initial_disordered() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    // Disorder the first packet(Initial) sent by the client
    let filter = Box::new(FirstPacketFilter::new(false));
    t.run_with_packet_filter(cli_conf, srv_conf, case_conf, filter)?;
    Ok(())
}

#[test]
fn transfer_single_stream_0rtt_reject() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestTool::new_test_config(false)?;
    let mut srv_conf = TestTool::new_test_config(true)?;
    let mut tls_config = TlsConfig::new_server_config(
        "src/tls/testdata/cert.crt",
        "src/tls/testdata/cert.key",
        vec![b"h3".to_vec()],
        true,
    )?;
    tls_config.set_ticket_key(&vec![0x01; 48])?;
    srv_conf.set_tls_config(tls_config);

    let mut case_conf = CaseConf::default();
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = false;
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_cubic_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_loss = 1;
    case_conf.cc_algor = CongestionControlAlgorithm::Cubic;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_bbr_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_loss = 1;
    case_conf.cc_algor = CongestionControlAlgorithm::Bbr;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_bbr3_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_loss = 1;
    case_conf.cc_algor = CongestionControlAlgorithm::Bbr3;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_copa_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_loss = 1;
    case_conf.cc_algor = CongestionControlAlgorithm::Copa;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_dummy_with_packet_loss() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_loss = 1;
    case_conf.cc_algor = CongestionControlAlgorithm::Dummy;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_with_packet_delay() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_delay = 20;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_with_packet_reorder() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_reorder = 2;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_with_packet_corruption() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_corruption = 1;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_with_packet_duplication() -> Result<()> {
    let mut t = TestPair::new();

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;
    case_conf.packet_duplication = 2;

    t.run_with_test_config(case_conf)?;
    Ok(())
}

#[test]
fn transfer_single_stream_disable_encryption() -> Result<()> {
    let mut t = TestPair::new();

    let mut cli_conf = TestPair::new_test_config(false)?;
    cli_conf.enable_encryption(false);
    let mut srv_conf = TestPair::new_test_config(true)?;
    srv_conf.enable_encryption(false);

    let mut case_conf = CaseConf::default();
    case_conf.session = Some(TestPair::new_test_session_state());
    case_conf.client_0rtt_expected = true;
    case_conf.resumption_expected = true;
    case_conf.request_num = 1;
    case_conf.request_size = 1024 * 16;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}

#[test]
fn transfer_multi_stream_normal() -> Result<()> {
    let mut t = TestPair::new();

    let cli_conf = TestPair::new_test_config(false)?;
    let srv_conf = TestPair::new_test_config(true)?;

    let mut case_conf = CaseConf::default();
    case_conf.request_num = 8;
    case_conf.request_size = 1024 * 8;

    t.run(cli_conf, srv_conf, case_conf)?;
    Ok(())
}
