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

//! Implementation of QUIC protocol.

#![allow(unused_variables)]

use core::ops::Range;
use std::any::Any;
use std::cell::RefCell;
use std::cmp;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time;

use bytes::Bytes;
use enumflags2::bitflags;
use enumflags2::BitFlags;
use log::*;
use strum::IntoEnumIterator;

use self::cid::ConnectionIdItem;
use self::space::BufferFlags;
use self::space::BufferType;
use self::space::PacketNumSpace;
use self::space::RateSamplePacketState;
use self::space::SpaceId;
use self::stream::Stream;
use self::stream::StreamIter;
use self::timer::Timer;
use self::ConnectionFlags::*;
use crate::codec;
use crate::codec::Decoder;
use crate::codec::Encoder;
use crate::error::ConnectionError;
use crate::error::Error;
use crate::frame;
use crate::frame::Frame;
use crate::multipath_scheduler::*;
use crate::packet;
use crate::packet::PacketHeader;
use crate::packet::PacketType;
#[cfg(feature = "qlog")]
use crate::qlog;
#[cfg(feature = "qlog")]
use crate::qlog::events;
use crate::tls;
use crate::tls::Keys;
use crate::tls::Level;
use crate::tls::Open;
use crate::tls::TlsSession;
use crate::token::AddressToken;
use crate::token::ResetToken;
use crate::trans_param::TransportParams;
use crate::Config;
use crate::ConnectionId;
use crate::ConnectionQueues;
use crate::Event;
use crate::EventQueue;
use crate::FourTuple;
use crate::FourTupleIter;
use crate::MultipathConfig;
use crate::PacketInfo;
use crate::PathEvent;
use crate::PathStats;
use crate::RecoveryConfig;
use crate::Result;
use crate::Shutdown;

/// A QUIC connection.
pub struct Connection {
    /// QUIC version used for the connection.
    version: u32,

    /// Whether this is a server connection.
    is_server: bool,

    /// Connection Identifiers.
    cids: cid::ConnectionIdMgr,

    /// Packet number spaces.
    spaces: space::PacketNumSpaceMap,

    /// The path manager.
    paths: path::PathMap,

    /// Multipath scheduler for MPQUIC
    multipath_scheduler: Option<Box<dyn MultipathScheduler>>,

    /// Config for multipath scheduler
    multipath_conf: MultipathConfig,

    /// The stream manager.
    streams: stream::StreamMap,

    /// TLS session.
    tls_session: TlsSession,

    /// The crypto streams for Initial/Handshake/1RTT level, each of which
    /// starts at an offset of 0.
    crypto_streams: Rc<RefCell<CryptoStreams>>,

    /// Raw packets that were received before decryption keys are available.
    undecryptable_packets: UndecryptablePackets,

    /// Peer transport parameters.
    peer_transport_params: TransportParams,

    /// Local transport parameters.
    local_transport_params: TransportParams,

    /// Recovery and congestion control configurations.
    recovery_conf: RecoveryConfig,

    /// Error to be sent to the peer in a CONNECTION_CLOSE frame.
    local_error: Option<ConnectionError>,

    /// Error received from the peer in a CONNECTION_CLOSE frame.
    peer_error: Option<ConnectionError>,

    /// Various connection timers.
    timers: timer::TimerTable,

    /// Various connection states.
    flags: BitFlags<ConnectionFlags>,

    /// Various connection metrics.
    stats: ConnectionStats,

    /// Original destination connection ID created by the client.
    odcid: Option<ConnectionId>,

    /// Retry source connection ID from server.
    rscid: Option<ConnectionId>,

    /// For client, it is the received address token from server;
    /// For server, it is the resume address token to issue to the client.
    token: Option<Vec<u8>>,

    /// Received DATAGRAM frames waiting to be read by the application.
    dgram_recv_queue: VecDeque<Bytes>,

    /// DATAGRAM frames queued for sending.
    dgram_send_queue: VecDeque<Bytes>,

    /// Internal Identifier of connection on the Endpoint.
    index: Option<u64>,

    /// Events to be sent to the endpoint.
    events: EventQueue,

    /// Status observed by the endpoint.
    queues: Option<Rc<RefCell<ConnectionQueues>>>,

    /// User context for the connection.
    context: Option<Box<dyn Any + Send + Sync>>,

    /// Qlog writer
    #[cfg(feature = "qlog")]
    qlog: Option<qlog::QlogWriter>,

    /// Unique trace id for debug logging
    trace_id: String,
}

impl Connection {
    /// Create a new QUIC client connection
    #[doc(hidden)]
    pub fn new_client(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        conf: &Config,
    ) -> Result<Self> {
        Connection::new(scid, local, remote, server_name, None, conf, false)
    }

    /// Create a new QUIC server connection
    #[doc(hidden)]
    pub fn new_server(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        token: Option<&AddressToken>,
        conf: &Config,
    ) -> Result<Self> {
        Connection::new(scid, local, remote, None, token, conf, true)
    }

    /// Create a new QUIC connection
    ///
    /// The `scid` is the local cid for the connection.
    /// The `addr_token` is optional and used to create the server connection. It
    /// is extracted from Initial packet with Token sent by the client connection.
    fn new(
        scid: &ConnectionId,
        local: SocketAddr,
        remote: SocketAddr,
        server_name: Option<&str>,
        addr_token: Option<&AddressToken>,
        conf: &Config,
        is_server: bool,
    ) -> Result<Self> {
        let trace_id = format!("{}-{}", if is_server { "SERVER" } else { "CLIENT" }, scid);

        let mut path = path::Path::new(local, remote, true, &conf.recovery, &trace_id);
        if is_server {
            // The server connection is created upon receiving an Initial packet
            // with a valid token sent by the client.
            path.verified_peer_address = addr_token.is_some();
            // The server connection assumes the peer has validate the server's
            // address implicitly.
            path.peer_verified_local_address = true;
        }

        let cid_limit = conf.local_transport_params.active_conn_id_limit as usize;
        let paths = path::PathMap::new(path, cid_limit, conf.anti_amplification_factor, is_server);

        let active_pid = paths.get_active_path_id()?;
        let reset_token = if is_server && conf.stateless_reset {
            // Note that clients cannot use the stateless_reset_token transport
            // parameter because their transport parameters do not have
            // confidentiality protection
            Some(ResetToken::generate(&conf.reset_token_key, scid).to_u128())
        } else {
            None
        };
        let cids = cid::ConnectionIdMgr::new(cid_limit, scid, active_pid, reset_token);

        let mut streams = stream::StreamMap::new(
            is_server,
            conf.max_connection_window,
            conf.max_stream_window,
            stream::StreamTransportParams::from(&conf.local_transport_params),
        );
        streams.set_trace_id(&trace_id);

        let mut tls_session = conf.new_tls_session(server_name, is_server)?;
        if let Some(tls_config_selector) = &conf.tls_config_selector {
            tls_session.set_config_selector(tls_config_selector.clone());
        }
        tls_session.set_trace_id(&trace_id);

        let mut conn = Connection {
            version: crate::QUIC_VERSION_V1,
            is_server,
            cids,
            spaces: space::PacketNumSpaceMap::new(),
            paths,
            multipath_scheduler: None,
            multipath_conf: conf.multipath.clone(),
            streams,
            tls_session,
            crypto_streams: Rc::new(RefCell::new(CryptoStreams::new())),
            undecryptable_packets: UndecryptablePackets::new(conf.max_undecryptable_packets),
            peer_transport_params: TransportParams::default(),
            local_transport_params: conf.local_transport_params.clone(),
            recovery_conf: conf.recovery.clone(),
            local_error: None,
            peer_error: None,
            timers: timer::TimerTable::default(),
            flags: BitFlags::default(),
            stats: ConnectionStats::default(),
            odcid: None,
            rscid: None,
            token: None,
            dgram_recv_queue: VecDeque::new(),
            dgram_send_queue: VecDeque::new(),
            index: None,
            events: EventQueue::default(),
            queues: None,
            context: None,
            #[cfg(feature = "qlog")]
            qlog: None,
            trace_id,
        };

        let write_method = conn.get_write_method();
        conn.tls_session.set_write_method(write_method);

        // When advertising the enable_multipath transport parameter, the
        // endpoint MUST use non-zero source and destination CIDs.
        if conn.cids.zero_length_scid() || conn.cids.zero_length_dcid() {
            conn.local_transport_params.enable_multipath = false;
        }

        conn.local_transport_params.initial_source_connection_id = Some(conn.cids.get_scid(0)?.cid);
        if let Some(addr_token) = addr_token {
            conn.local_transport_params
                .original_destination_connection_id = addr_token.odcid;
            conn.local_transport_params.retry_source_connection_id = addr_token.rscid;
            conn.flags.insert(DidRetry);
        }
        conn.local_transport_params.stateless_reset_token = reset_token;
        conn.set_transport_params()?;

        // Derive initial secrets for the client.
        if !is_server {
            let dcid = ConnectionId::random(); // original dcid created by client
            let reset_token = conn.peer_transport_params.stateless_reset_token;
            conn.set_initial_dcid(dcid, reset_token, active_pid)?;

            conn.tls_session
                .derive_initial_secrets(&dcid, conn.version)?;
            conn.flags.insert(DerivedInitialSecrets);
        }

        if !conf.max_handshake_timeout.is_zero() {
            conn.timers.set(
                Timer::Handshake,
                time::Instant::now() + conf.max_handshake_timeout,
            );
        }

        // Prepare resume address token if needed
        if is_server {
            let token = AddressToken::new_resume_token(remote);
            if let Ok(token) = token.encode(&conf.address_token_key[0]) {
                conn.token = Some(token);
            }
        }

        Ok(conn)
    }

    /// Configure the given session data for resumption.
    pub fn set_session(&mut self, mut buf: &[u8]) -> Result<()> {
        let session_len = buf.read_u64()? as usize;
        let session_bytes = buf.read(session_len)?;
        self.tls_session.set_session(&session_bytes)?;

        let params_len = buf.read_u64()? as usize;
        let params_bytes = buf.read(params_len)?;
        let (peer_params, _) = TransportParams::decode(&params_bytes, self.is_server)?;
        self.set_peer_trans_params(peer_params)?;

        Ok(())
    }

    /// Set address token used by the client connection.
    pub fn set_token(&mut self, token: Vec<u8>) -> Result<()> {
        if self.is_server {
            return Err(Error::InvalidOperation("not a client".into()));
        }
        self.token = Some(token);
        Ok(())
    }

    /// Set keylog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    pub fn set_keylog(&mut self, writer: Box<dyn std::io::Write + Send + Sync>) {
        self.tls_session.set_keylog(writer);
    }

    /// Set qlog output to the given [`writer`]
    ///
    /// [`Writer`]: https://doc.rust-lang.org/std/io/trait.Write.html
    #[cfg(feature = "qlog")]
    pub fn set_qlog(
        &mut self,
        writer: Box<dyn std::io::Write + Send + Sync>,
        title: String,
        description: String,
    ) {
        let trace = qlog::TraceSeq::new(
            Some(title.to_string()),
            Some(description.to_string()),
            None,
            qlog::VantagePoint::new(None, self.is_server),
        );
        let level = events::EventImportance::Extra;
        let mut writer = qlog::QlogWriter::new(
            Some(title),
            Some(description),
            trace,
            level,
            writer,
            time::Instant::now(),
        );
        writer.start().ok();

        // Write TransportParametersSet event to qlog
        Self::qlog_quic_params_set(
            &mut writer,
            &self.local_transport_params,
            events::Owner::Local,
            self.tls_session.cipher(),
        );

        self.qlog = Some(writer);
    }
}

/// A set of crypto streams for Initial/Handshake/1RTT level.
struct CryptoStreams {
    streams: [Stream; 3],
}

impl CryptoStreams {
    /// Create crypto streams for Initial/Handshake/1RTT level.
    pub fn new() -> Self {
        CryptoStreams {
            streams: [
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
                CryptoStreams::new_stream(),
            ],
        }
    }

    /// Get crypto stream for the given encryption level.
    pub fn get_mut(&mut self, level: Level) -> Result<&mut Stream> {
        match level {
            Level::Initial => Ok(&mut self.streams[0]),
            Level::Handshake => Ok(&mut self.streams[1]),
            Level::OneRTT => Ok(&mut self.streams[2]),
            _ => Err(Error::InternalError),
        }
    }

    /// Clear a crypto stream when dropping the corresponding keys.
    pub fn clear(&mut self, level: Level) {
        match level {
            Level::Initial => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            Level::Handshake => {
                self.streams[0] = CryptoStreams::new_stream();
            }
            _ => (),
        }
    }

    /// Create a crypto stream.
    ///
    /// Data sent in CRYPTO frames is not flow controlled in the same way as
    /// stream data. QUIC relies on the implementation to avoid excessive
    /// buffering of data
    fn new_stream() -> Stream {
        Stream::new(true, true, u64::MAX, u64::MAX, stream::MAX_STREAM_WINDOW)
    }
}

/// Collection of packets which were received before decryption keys are available.
struct UndecryptablePackets {
    zerortt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    handshake_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    onertt_pkts: VecDeque<(Vec<u8>, PacketInfo)>,
    capacity: usize,
}

impl UndecryptablePackets {
    fn new(capacity: usize) -> Self {
        Self {
            zerortt_pkts: VecDeque::with_capacity(capacity),
            handshake_pkts: VecDeque::with_capacity(capacity),
            onertt_pkts: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    fn push(&mut self, pkt_type: &PacketType, pkt: Vec<u8>, info: &PacketInfo) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => {
                if self.zerortt_pkts.len() > self.capacity {
                    false
                } else {
                    self.zerortt_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::Handshake => {
                if self.handshake_pkts.len() > self.capacity {
                    false
                } else {
                    self.handshake_pkts.push_back((pkt, *info));
                    true
                }
            }
            PacketType::OneRTT => {
                if self.onertt_pkts.len() > self.capacity {
                    false
                } else {
                    self.onertt_pkts.push_back((pkt, *info));
                    true
                }
            }
            _ => false,
        }
    }

    fn pop(&mut self, pkt_type: &PacketType) -> Option<(Vec<u8>, PacketInfo)> {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.pop_front(),
            PacketType::Handshake => self.handshake_pkts.pop_front(),
            PacketType::OneRTT => self.onertt_pkts.pop_front(),
            _ => None,
        }
    }

    fn is_empty(&self, pkt_type: &PacketType) -> bool {
        match pkt_type {
            PacketType::ZeroRTT => self.zerortt_pkts.is_empty(),
            PacketType::Handshake => self.handshake_pkts.is_empty(),
            PacketType::OneRTT => self.onertt_pkts.is_empty(),
            _ => true,
        }
    }

    fn all_empty(&self) -> bool {
        self.zerortt_pkts.is_empty()
            && self.handshake_pkts.is_empty()
            && self.onertt_pkts.is_empty()
    }
}

/// Various flags of QUIC connection
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy)]
enum ConnectionFlags {
    /// The version negotiation has been performed.
    DidVersionNegotiation = 1 << 0,

    /// The stateless retry has been performed.
    DidRetry = 1 << 1,

    /// The initial secrets have been derived.
    DerivedInitialSecrets = 1 << 2,

    /// The client's session has been started to handshake.
    InitiatedClientHandshake = 1 << 3,

    /// The peer's cid has been saved.
    GotPeerCid = 1 << 4,

    /// The peer's transport parameters have been processed.
    AppliedPeerTransportParams = 1 << 5,

    /// The peer has verified local initial address.
    PeerVerifiedInitialAddress = 1 << 6,

    /// The handshake has been completed.
    HandshakeCompleted = 1 << 7,

    /// The connection has been confirmed.
    HandshakeConfirmed = 1 << 8,

    /// The connection has been closed.
    Closed = 1 << 9,

    /// The connection was closed due to the idle timeout.
    IdleTimeout = 1 << 10,

    /// The connection was closed due to handshake timeout.
    HandshakeTimeout = 1 << 11,

    /// The connection was closed due to stateless reset.
    GotReset = 1 << 12,

    /// An ack-eliciting packet should be sent.
    NeedSendAckEliciting = 1 << 13,

    /// A NewToken frame should be sent.
    NeedSendNewToken = 1 << 14,

    /// A HandshakeDone frame should be sent.
    NeedSendHandshakeDone = 1 << 15,

    /// The client has acknowledged the server's HandshakeDone.
    HandshakeDoneAcked = 1 << 16,

    /// The connection has sent an ack-eliciting packet since receiving a packet.
    /// It is used for resetting Idle timer.
    SentAckElicitingSinceRecvPkt = 1 << 17,

    /// The connection is in the tickable queue of the endpoint.
    Tickable = 1 << 18,

    /// The connection is in the sendable queue of the endpoint.
    Sendable = 1 << 19,

    /// The multipath extension is successfully negotiated.
    EnableMultipath = 1 << 20,

    /// The disable_1rtt_encryption is successfully negotiated.
    DisableEncryption = 1 << 21,
}

/// Statistics about a QUIC connection.
#[repr(C)]
#[derive(Default)]
pub struct ConnectionStats {
    /// Total number of received packets.
    pub recv_count: u64,

    /// Total number of bytes received on the connection.
    pub recv_bytes: u64,

    /// Total number of sent packets.
    pub sent_count: u64,

    /// Total number of bytes sent on the connection.
    pub sent_bytes: u64,

    /// Total number of lost packets.
    pub lost_count: u64,

    /// Total number of bytes lost on the connection.
    pub lost_bytes: u64,
}

/// FrameWriteStatus is used to collect various states during writing frames
/// to a QUIC packet.
#[derive(Clone, Debug, Default)]
struct FrameWriteStatus {
    /// Number of bytes written to the packet payload
    written: usize,

    /// Frames written to the packet payload
    frames: Vec<Frame>,

    /// Whether it contains frames other than ACK, PADDING, and CONNECTION_CLOSE
    ack_eliciting: bool,

    /// Whether it is an in-flight packet (ack-eliciting packet or contain a
    /// PADDING frame)
    in_flight: bool,

    /// Whether it contains CRYPTO or STREAM frame
    has_data: bool,

    /// Whether it contains a PATH_CHALLENGE frame
    challenge: Option<[u8; 8]>,

    /// Whether a PING frame should be added to elicit an ACK from the peer.
    ack_elicit_required: bool,

    /// Whether the congestion window should be ignored.
    is_probe: bool,

    /// Whether it is a PMTU probe packet
    is_pmtu_probe: bool,

    /// Whether it consumes the pacer's tokens
    pacing: bool,

    /// Packet overhead (i.e. packet header and crypto overhead) in bytes
    overhead: usize,

    /// Status about buffered frames written to the packet.
    buffer_flags: BufferFlags,
}

/// Handshake status for loss recovery
#[derive(Clone, Copy, Debug)]
struct HandshakeStatus {
    /// Whether the Handshake keys have been derived.
    derived_handshake_keys: bool,

    /// Whether the peer has verified local initial address.
    peer_verified_address: bool,

    /// whether the connection handshake is complete.
    completed: bool,

    /// Whether this endpoint is a server.
    is_server: bool,

    /// Whether the server is at the anti-amplification limit.
    /// This is true when the server cannot send any more data until it
    /// receives more data from the client.
    at_amplification_limit: bool,
}

mod dgram;
mod handshake;
mod query;
mod recv;
mod send;

#[cfg(test)]
pub(crate) mod tests;

mod cid;
mod flowcontrol;
pub mod path;
mod pmtu;
mod recovery;
pub(crate) mod rtt;
pub(crate) mod space;
pub(crate) mod stream;
pub(crate) mod timer;
