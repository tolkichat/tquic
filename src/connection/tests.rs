    use self::path::PathState;
    use super::*;
    use crate::multipath_scheduler::MultipathAlgorithm;
    use crate::packet;
    use crate::ranges::RangeSet;
    use crate::tls::tests::ServerConfigSelector;
    use crate::tls::TlsConfig;
    use crate::tls::TlsConfigSelector;
    use crate::token::ResetToken;
    use crate::CongestionControlAlgorithm;
    use crate::ConnectionIdGenerator;
    use crate::RandomConnectionIdGenerator;
    use bytes::BytesMut;
    use rand::prelude::SliceRandom;
    use rand::thread_rng;
    use rand::RngCore;
    use ring::aead;
    use ring::aead::LessSafeKey;
    use ring::aead::UnboundKey;
    use std::io::Read;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    pub struct TestPair {
        pub client: Connection,
        pub server: Connection,
    }

    impl TestPair {
        pub fn new(client_config: &mut Config, server_config: &mut Config) -> Result<TestPair> {
            Self::new_with_server_name(client_config, server_config, "example.org")
        }

        pub fn new_with_server_name(
            client_config: &mut Config,
            server_config: &mut Config,
            server_name: &str,
        ) -> Result<TestPair> {
            let mut cli_cid_gen = RandomConnectionIdGenerator::new(client_config.cid_len);
            let mut srv_cid_gen = RandomConnectionIdGenerator::new(server_config.cid_len);
            let client_scid = cli_cid_gen.generate();
            let server_scid = srv_cid_gen.generate();
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

            Ok(TestPair {
                client: Connection::new_client(
                    &client_scid,
                    client_addr,
                    server_addr,
                    Some(server_name),
                    client_config,
                )?,
                server: Connection::new_server(
                    &server_scid,
                    server_addr,
                    client_addr,
                    None,
                    server_config,
                )?,
            })
        }

        pub fn new_with_test_config() -> Result<TestPair> {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.cid_len = crate::MAX_CID_LEN;
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.cid_len = crate::MAX_CID_LEN;
            TestPair::new(&mut client_config, &mut server_config)
        }

        pub fn new_with_zero_cid() -> Result<TestPair> {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.cid_len = 0;
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.cid_len = 0;
            TestPair::new(&mut client_config, &mut server_config)
        }

        /// Establish QUIC connection between client and server
        pub fn handshake(&mut self) -> Result<()> {
            while !self.client.is_established() || !self.server.is_established() {
                // client conn send all packets to server conn
                let packets = TestPair::conn_packets_out(&mut self.client)?;
                TestPair::conn_packets_in(&mut self.server, packets)?;

                // server conn send all packets to client conn
                let packets = TestPair::conn_packets_out(&mut self.server)?;
                TestPair::conn_packets_in(&mut self.client, packets)?;
            }
            Ok(())
        }

        pub fn move_forward(&mut self) -> Result<()> {
            let mut client_done = false;
            let mut server_done = false;

            while !client_done || !server_done {
                match TestPair::conn_packets_out(&mut self.client) {
                    Ok(flight) => {
                        if flight.is_empty() {
                            client_done = true;
                        } else {
                            TestPair::conn_packets_in(&mut self.server, flight)?;
                        }
                    }
                    Err(Error::Done) => client_done = true,
                    Err(e) => return Err(e),
                };

                match TestPair::conn_packets_out(&mut self.server) {
                    Ok(flight) => {
                        if flight.is_empty() {
                            server_done = true;
                        } else {
                            TestPair::conn_packets_in(&mut self.client, flight)?;
                        }
                    }
                    Err(Error::Done) => server_done = true,
                    Err(e) => return Err(e),
                };
            }

            Ok(())
        }

        /// Generate all outgoing packets
        pub fn conn_packets_out(conn: &mut Connection) -> Result<Vec<(Vec<u8>, PacketInfo)>> {
            let mut packets = Vec::new();
            loop {
                let mut out = vec![0u8; 1500];
                let info = match conn.send(&mut out) {
                    Ok((written, info)) => {
                        out.truncate(written);
                        info
                    }
                    Err(Error::BufferTooShort) => break,
                    Err(Error::Done) => break,
                    Err(e) => return Err(e),
                };
                packets.push((out, info));
            }
            Ok(packets)
        }

        /// Process all incoming packets
        fn conn_packets_in(
            conn: &mut Connection,
            packets: Vec<(Vec<u8>, PacketInfo)>,
        ) -> Result<()> {
            for (mut pkt, info) in packets {
                match conn.recv(&mut pkt, &info) {
                    Ok(_) => (),
                    Err(Error::Done) => (),
                    Err(e) => return Err(e),
                }
            }
            Ok(())
        }

        /// Build an outgoing packet with the given frames on the active path of the connection.
        pub fn conn_build_packet(
            conn: &mut Connection,
            pkt_type: PacketType,
            frames: &[frame::Frame],
        ) -> Result<Vec<u8>> {
            let mut packet = vec![0; 1500];
            let buf = &mut packet;

            let path = conn.paths.get_active()?;
            let dcid_seq = path.dcid_seq.ok_or(Error::InternalError)?;
            let dcid = conn.cids.get_dcid(dcid_seq)?.cid;
            let scid = if let Some(scid_seq) = path.scid_seq {
                conn.cids.get_scid(scid_seq)?.cid
            } else if pkt_type == PacketType::OneRTT {
                ConnectionId::default()
            } else {
                return Err(Error::InternalError);
            };

            let space_id = pkt_type.to_space()?;
            let space = conn.spaces.get_mut(space_id).unwrap();
            let pkt_num = space.next_pkt_num;
            let pkt_num_len = 4;

            // Write packet header
            let pkt_hdr = PacketHeader {
                pkt_type,
                version: conn.version,
                dcid,
                scid,
                pkt_num: 0,
                pkt_num_len,
                token: conn.token.clone(),
                key_phase: false,
            };
            let hdr_offset = pkt_hdr.to_bytes(buf)?;

            // Fill Length field
            let mut bw = &mut buf[hdr_offset..];
            let payload_len = frames.iter().fold(0, |sum, f| sum + f.wire_len());
            let crypto_overhead = conn
                .tls_session
                .get_overhead(pkt_type.to_level()?)
                .ok_or(Error::InternalError)?;
            if pkt_type != PacketType::OneRTT {
                let length = pkt_num_len + payload_len + crypto_overhead;
                bw.write_varint_with_len(length as u64, crate::LENGTH_FIELD_LEN)?;
            }

            // Fill packet number field
            bw.write_u32(pkt_num as u32)?;

            // Write packet payload
            let payload_offset = if pkt_type != PacketType::OneRTT {
                hdr_offset + crate::LENGTH_FIELD_LEN + pkt_num_len
            } else {
                hdr_offset + pkt_num_len
            };
            let mut off = payload_offset;
            for frame in frames {
                off += frame.to_bytes(&mut buf[off..])?;
            }

            // Encrypt the packet
            let key = conn.tls_session.get_keys(pkt_type.to_level()?);
            let key = match &key.seal {
                Some(seal) => seal,
                None => return Err(Error::InternalError),
            };
            let written = packet::encrypt_packet(
                buf,
                None,
                pkt_num,
                pkt_num_len,
                payload_len,
                payload_offset,
                None,
                key,
            )?;
            space.next_pkt_num += 1;

            packet.truncate(written);
            Ok(packet)
        }

        /// Build an outgoing packet with the given frames on the connection and send it to the peer.
        pub fn build_packet_and_send(
            &mut self,
            pkt_type: PacketType,
            frames: &[frame::Frame],
            is_server: bool,
        ) -> Result<()> {
            let (local_conn, peer_conn) = match is_server {
                false => (&mut self.client, &mut self.server),
                true => (&mut self.server, &mut self.client),
            };

            // Local connection build packet.
            let packet = TestPair::conn_build_packet(local_conn, PacketType::OneRTT, frames)?;
            let info = TestPair::new_test_packet_info(is_server);

            // Peer connection receive OneRTT packet
            TestPair::conn_packets_in(peer_conn, vec![(packet, info)])?;

            Ok(())
        }

        /// Create default test config
        pub fn new_test_config(is_server: bool) -> Result<Config> {
            let mut conf = Config::new()?;
            conf.set_initial_max_data(90);
            conf.set_initial_max_stream_data_bidi_local(50);
            conf.set_initial_max_stream_data_bidi_remote(40);
            conf.set_initial_max_stream_data_uni(30);
            conf.set_initial_max_streams_bidi(3);
            conf.set_initial_max_streams_uni(2);
            conf.set_recv_udp_payload_size(6000);
            conf.set_max_connection_window(1024 * 1024);
            conf.set_max_stream_window(1024 * 1024);
            conf.set_max_concurrent_conns(10);
            conf.set_active_connection_id_limit(2);
            conf.set_ack_delay_exponent(3);
            conf.set_max_ack_delay(25);
            conf.set_congestion_control_algorithm(CongestionControlAlgorithm::Cubic);
            conf.set_initial_congestion_window(10);
            conf.set_min_congestion_window(2);
            conf.set_reset_token_key([1u8; 64]);
            conf.set_address_token_lifetime(3600);
            conf.set_send_batch_size(2);
            conf.set_max_handshake_timeout(0);
            conf.enable_multipath(false);
            conf.enable_dplpmtud(true);
            conf.enable_pacing(false);

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

        /// Create default test packet info
        pub fn new_test_packet_info(is_server: bool) -> PacketInfo {
            let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
            let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

            PacketInfo {
                src: if is_server { server_addr } else { client_addr },
                dst: if is_server { client_addr } else { server_addr },
                time: time::Instant::now(),
            }
        }

        /// Create default test Stream frame
        pub fn new_test_stream_frame(content: &[u8]) -> frame::Frame {
            frame::Frame::Stream {
                stream_id: 0,
                offset: 0,
                length: content.len(),
                fin: false,
                data: Bytes::copy_from_slice(content),
            }
        }

        /// Assemble new version negotiation packet.
        fn new_test_version_negotiation_packet(
            dcid: &ConnectionId,
            scid: &ConnectionId,
            versions: &[u8],
        ) -> Vec<u8> {
            let mut pkt = vec![
                0x80, // Header form and unused bits.
                0x00, 0x00, 0x00, 0x00, // The Version field must be set to 0x00000000.
            ];

            // Append DCID.
            pkt.push(dcid.len);
            pkt.append(&mut dcid.data.to_vec());
            // Append SCID.
            pkt.push(scid.len);
            pkt.append(&mut scid.data.to_vec());
            // Append supported versions.
            let mut versions = versions.to_vec();
            pkt.append(&mut versions);

            pkt
        }

        /// Create random test data
        pub fn new_test_data(len: usize) -> bytes::Bytes {
            let mut data = BytesMut::with_capacity(len);
            data.resize(len, 0);
            rand::thread_rng().fill_bytes(&mut data);
            data.freeze()
        }

        /// Advertise new cids for each other
        pub fn advertise_new_cids(&mut self) -> Result<()> {
            let (scid, reset_token) = (ConnectionId::random(), Some(1));
            self.client
                .cids
                .add_scid(scid, reset_token, true, None, true)?;
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;

            let (scid, reset_token) = (ConnectionId::random(), Some(2));
            self.server
                .cids
                .add_scid(scid, reset_token, true, None, true)?;
            let packets = TestPair::conn_packets_out(&mut self.server)?;
            TestPair::conn_packets_in(&mut self.client, packets)?;
            Ok(())
        }

        /// Client add a new path and initiate the path validation
        pub fn add_and_validate_path(
            &mut self,
            client_addr: SocketAddr,
            server_addr: SocketAddr,
        ) -> Result<()> {
            self.client.add_path(client_addr, server_addr)?;

            // Client send PATH_CHALLENGE
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;

            // Server send PATH_RESPONSE/PATH_CHALLENGE
            let packets = TestPair::conn_packets_out(&mut self.server)?;
            TestPair::conn_packets_in(&mut self.client, packets)?;

            // Client send PATH_RESPONSE
            let packets = TestPair::conn_packets_out(&mut self.client)?;
            TestPair::conn_packets_in(&mut self.server, packets)?;
            Ok(())
        }
    }

    #[test]
    fn version_negotiation_with_unknown_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert_eq!(
            test_pair.client.recv(&mut pkt, &info),
            Err(Error::UnknownVersion)
        );

        Ok(())
    }

    #[test]
    fn version_negotiation_with_same_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x01],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_dcid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.dcid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_scid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Assemble version negotiation packet.
        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.scid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_with_invalid_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0xFF],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn version_negotiation_after_other_packet() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(true);
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut pkt = TestPair::new_test_version_negotiation_packet(
            test_pair.client.scid().as_ref().unwrap(),
            test_pair.client.dcid().as_ref().unwrap(),
            &vec![0x00, 0x00, 0x00, 0x00],
        );

        assert!(test_pair.client.recv(&mut pkt, &info).is_ok());
        assert!(!test_pair.client.flags.contains(DidVersionNegotiation));

        Ok(())
    }

    #[test]
    fn handshake_complete() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_none());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_none());
        assert_eq!(test_pair.client.is_server(), false);
        assert_eq!(test_pair.server.is_server(), true);

        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        assert_eq!(test_pair.client.scid(), test_pair.server.dcid());
        assert_eq!(test_pair.server.scid(), test_pair.client.dcid());
        assert_eq!(test_pair.client.odcid(), test_pair.server.odcid());

        assert_eq!(test_pair.client.local_error(), None);
        assert_eq!(test_pair.server.local_error(), None);
        assert_eq!(test_pair.client.peer_error(), None);
        assert_eq!(test_pair.server.peer_error(), None);

        assert_eq!(test_pair.client.application_proto(), b"h3");
        assert_eq!(test_pair.client.server_name(), Some("example.org"));

        Ok(())
    }

    #[test]
    fn handshake_resume() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.client.is_resumed(), false);
        assert_eq!(test_pair.server.is_resumed(), false);

        // Client extract session state for resumption
        let session = test_pair.client.session().unwrap();

        // Client perform the second handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.client.is_resumed(), true);
        assert_eq!(test_pair.server.is_resumed(), true);
        assert_eq!(test_pair.client.application_proto(), b"h3");
        assert_eq!(test_pair.client.application_proto(), b"h3");

        Ok(())
    }

    #[test]
    fn handshake_confirm() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_confirmed(), false);
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake and completes handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_confirmed(), false);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server complete and confirm handshake, send HANDSHAKE_DONE
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), false);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.server.is_confirmed(), true);

        // Client confirm handshake
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.client.is_confirmed(), true);
        assert_eq!(test_pair.server.is_established(), true);
        assert_eq!(test_pair.server.is_confirmed(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_version_negotiation() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Inject a Version Negotiation packet to client
        let (initial_pkt, initial_info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;
        let mut buf = vec![0; 256];
        let len = packet::version_negotiation(&hdr.dcid, &hdr.scid, &mut buf)?;
        buf.truncate(len);
        let info = PacketInfo {
            src: initial_info.dst,
            dst: initial_info.src,
            time: initial_info.time,
        };

        // Client drop the Version Negotiation packet with the same version.
        TestPair::conn_packets_in(&mut test_pair.client, vec![(buf, info)])?;

        // Client/Server continue the handshake
        TestPair::conn_packets_in(&mut test_pair.server, vec![(initial_pkt, initial_info)])?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_retry() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let lifetime = Duration::from_secs(86400);

        // Client send Initial without token
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Server build a Retry
        let (initial_pkt, info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;

        let key = LessSafeKey::new(UnboundKey::new(&aead::AES_128_GCM, &[1; 16]).unwrap());
        let retry_scid = ConnectionId::random();
        let token = AddressToken::new_retry_token(client_addr, hdr.dcid, retry_scid);
        let token = token.encode(&key)?;

        let mut buf = vec![0; 256];
        let len = packet::retry(
            &retry_scid,
            &hdr.scid,
            &hdr.dcid,
            &token,
            crate::QUIC_VERSION_V1,
            &mut buf,
        )?;
        buf.truncate(len);
        let info = PacketInfo {
            src: info.dst,
            dst: info.src,
            time: info.time,
        };

        // Client recv Retry
        TestPair::conn_packets_in(&mut test_pair.client, vec![(buf, info)])?;

        // Client send Initial with token
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Server validate token in Initial
        let (mut initial_pkt, info) = packets.pop().unwrap();
        let hdr = PacketHeader::from_bytes(&initial_pkt, 20)?.0;
        assert!(hdr.token.is_some());
        let token = AddressToken::decode(
            &key,
            &mut hdr.token.unwrap(),
            &client_addr,
            &hdr.dcid,
            lifetime,
        )?;

        // Server create server-side conn
        let server_iscid = ConnectionId::random();
        test_pair.server = Connection::new_server(
            &server_iscid,
            server_addr,
            client_addr,
            Some(&token),
            &mut TestPair::new_test_config(true)?,
        )?;
        test_pair.server.recv(&mut initial_pkt, &info)?;

        // Client/Server continue the handshake
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_0rtt_data() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client extract session state and try to perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!packets.is_empty());

        // Client send ZeroRTT packet
        let content = "client zero rtt data";
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::ZeroRTT, &[frame])?;
        let info = packets.first().unwrap().1;

        // Server recv Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert!(test_pair.client.is_in_early_data());

        // Server recv ZeroRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.server.streams.has_readable_streams());

        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());

        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_0rtt_reordered_server_side() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client perform the resumed handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!packets.is_empty());

        // Client send ZeroRTT packet
        let content = "client zero rtt data before initial";
        let mut frames = vec![];
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        frames.push(frame);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::ZeroRTT, &frames)?;
        let info = packets.first().unwrap().1;

        // Server recv ZeroRTT packet before Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.client.is_in_early_data());
        assert!(!test_pair.server.streams.has_readable_streams());
        assert!(!test_pair
            .server
            .undecryptable_packets
            .zerortt_pkts
            .is_empty());

        // Server recv the reordered Initial packet
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.is_in_early_data(), true);
        assert!(test_pair
            .server
            .undecryptable_packets
            .zerortt_pkts
            .is_empty());
        assert!(test_pair.server.streams.has_readable_streams());
        let stream = test_pair.server.streams.get_mut(0).unwrap();
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_1rtt_reordered_server_side() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send and server recv Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send and client recv Initial and Handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.is_established());

        // Client send OneRTT packet.
        let content = "client one rtt data before handshake";
        let mut frames = vec![];
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        frames.push(frame);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &frames)?;

        // Client send Handshake packets.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let info = packets.first().unwrap().1;

        // Server recv OneRTT packet before Handshake packets.
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(!test_pair.server.is_confirmed());
        assert!(!test_pair
            .server
            .undecryptable_packets
            .onertt_pkts
            .is_empty());

        // Server recv the reordered Handshake packets.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert!(test_pair.server.is_confirmed());
        assert!(test_pair
            .server
            .tls_session
            .get_keys(Level::OneRTT)
            .open
            .is_some());
        assert!(test_pair.server.streams.has_readable_streams());
        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);

        Ok(())
    }

    #[test]
    fn handshake_with_handshake_reordered_client_side() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.flags.contains(HandshakeConfirmed), false);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.flags.contains(HandshakeConfirmed), false);

        // Client recv Handshake before Initial.
        TestPair::conn_packets_in(&mut test_pair.client, vec![packets[1].clone()])?;
        assert_eq!(test_pair.client.is_established(), false);
        let undecryptable_handshake_packets =
            &test_pair.client.undecryptable_packets.handshake_pkts;
        assert_eq!(undecryptable_handshake_packets.is_empty(), false);
        TestPair::conn_packets_in(&mut test_pair.client, vec![packets[0].clone()])?;
        assert_eq!(test_pair.client.is_established(), true);
        let undecryptable_handshake_packets =
            &test_pair.client.undecryptable_packets.handshake_pkts;
        assert_eq!(undecryptable_handshake_packets.is_empty(), true);

        // Client send Initial/Handshake(ack)
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Continue handshake
        test_pair.handshake()?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_packet_loss() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Fake dropping client Initial packets
        packets.clear();
        let timeout = test_pair.client.timeout();
        let loss_time = test_pair.client.timers.get(Timer::LossDetection);
        assert!(loss_time.is_some());

        // Advance ticks until loss timeout
        let now = loss_time.unwrap();
        test_pair.client.on_timeout(now);
        packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake and complete handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), false);
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server complete handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_packet_corrupted() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send a Handshake but the packet is corrupted
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());
        let packet = &mut packets[0].0;
        let packet_len = packet.len();
        packet[packet_len - 1] = packet[packet_len - 1].wrapping_add(1);

        // Server recv a corrupted Handshake
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), false);

        // Client resend Handshake
        let timeout = test_pair.client.timeout();
        let loss_time = test_pair.client.timers.get(Timer::LossDetection);
        assert!(loss_time.is_some());
        test_pair.client.on_timeout(loss_time.unwrap());
        packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server complete handshake
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_anti_amplification_deadlock() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Client send Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial and Handshake.
        let mut packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Fake dropping the second Handshake packet.
        packets.truncate(1);

        // Client recv Initial and the first Handshake.
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(!test_pair.client.tls_session.is_completed());

        // Client send ACK and PADDING and wait for retransmission of the second packet.
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client must set LossDetection timer to avoid deadlock
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::LossDetection).is_some());

        // Server retransmit Handshake but lost again
        for i in 0..5 {
            let dur = test_pair.server.timeout().unwrap();
            test_pair.server.on_timeout(time::Instant::now() + dur);
            let _ = TestPair::conn_packets_out(&mut test_pair.server)?;
        }

        // Server is blocked by anti-amplification limit
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(path.anti_ampl_limit, 0);
        }

        // A deadlock could occur when the server reaches its anti-amplification limit
        // and the client has received acknowledgments for all the data it has sent.
        // In this case, when the client has no reason to send additional packets, the
        // server will be unable to send more data because it has not validated the
        // client's address. To prevent this deadlock, clients MUST send a packet on a
        // Probe Timeout (PTO).
        let dur = test_pair.client.timeout().unwrap();
        test_pair.client.on_timeout(time::Instant::now() + dur);
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());

        // Server and client continue the handshake.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert!(path.anti_ampl_limit > 0);
        }
        let dur = test_pair.server.timeout().unwrap();
        test_pair.server.on_timeout(time::Instant::now() + dur);

        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(test_pair.client.is_established(), true);
        assert_eq!(test_pair.server.is_established(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_alpn_mismatched() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        let tls_config = TlsConfig::new_server_config(
            "src/tls/testdata/cert.crt",
            "src/tls/testdata/cert.key",
            vec![b"http/0.9".to_vec()],
            true,
        )?;
        server_config.set_tls_config(tls_config);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.handshake().is_err());

        Ok(())
    }

    #[test]
    fn handshake_with_timeout_enabled() -> Result<()> {
        const TIMEOUT: u64 = 3 * 1000;
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        client_config.set_max_handshake_timeout(TIMEOUT);
        server_config.set_max_handshake_timeout(TIMEOUT);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_some());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_some());

        assert_eq!(test_pair.handshake(), Ok(()));
        assert!(test_pair.client.is_established());
        assert!(test_pair.server.is_established());
        assert!(test_pair.client.timers.get(Timer::Handshake).is_none());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_none());

        Ok(())
    }

    #[test]
    fn handshake_with_timeout_failed() -> Result<()> {
        const CLIENT_TIMEOUT: u64 = 60 * 1000;
        const SERVER_TIMEOUT: u64 = 30 * 1000;
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        client_config.set_max_handshake_timeout(CLIENT_TIMEOUT);
        server_config.set_max_handshake_timeout(SERVER_TIMEOUT);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert!(test_pair.client.timers.get(Timer::Handshake).is_some());
        assert!(test_pair.server.timers.get(Timer::Handshake).is_some());

        // Client send all packets to server.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Fake losing server packets.
        let _ = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Fake timing out server's Handshake timer.
        let now = time::Instant::now() + time::Duration::from_millis(SERVER_TIMEOUT);
        test_pair.server.on_timeout(now);
        assert_eq!(test_pair.server.is_established(), false);
        assert_eq!(test_pair.server.is_closed(), true);
        assert_eq!(test_pair.server.is_handshake_timeout(), true);

        // Fake timing out client's Handshake timer.
        let now = time::Instant::now() + time::Duration::from_millis(CLIENT_TIMEOUT);
        test_pair.client.on_timeout(now);
        assert_eq!(test_pair.client.is_established(), false);
        assert_eq!(test_pair.client.is_closed(), true);
        assert_eq!(test_pair.client.is_handshake_timeout(), true);

        Ok(())
    }

    #[test]
    fn handshake_with_keylog() {
        let logger = NamedTempFile::new().unwrap();
        let mut f = logger.reopen().unwrap();

        let mut test_pair = TestPair::new_with_test_config().unwrap();
        test_pair.server.set_keylog(Box::new(logger));
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut log = String::new();
        f.read_to_string(&mut log).unwrap();
        assert_eq!(log.is_empty(), false);
        assert_eq!(log.contains("TRAFFIC_SECRET"), true);
    }

    #[test]
    fn handshake_multi_cert_with_known_sni() -> Result<()> {
        // New config selector.
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_tls_config_selector(conf_selector.clone());

        for i in 0..conf_selector.len() {
            let mut test_pair = TestPair::new_with_server_name(
                &mut client_config,
                &mut server_config,
                &i.to_string(),
            )?;

            assert!(test_pair.handshake().is_ok());
            assert!(test_pair.client.is_established());
            assert!(test_pair.server.is_established());
        }

        Ok(())
    }

    #[test]
    fn handshake_multi_cert_with_unknown_sni() -> Result<()> {
        // New config selector.
        let conf_selector = Arc::new(ServerConfigSelector::new()?);

        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_tls_config_selector(conf_selector.clone());

        let mut test_pair = TestPair::new_with_server_name(
            &mut client_config,
            &mut server_config,
            &"unknown".to_string(),
        )?;

        assert!(!test_pair.handshake().is_ok());

        Ok(())
    }

    #[test]
    fn handshake_with_multipath_negotiated() -> Result<()> {
        let cases = [
            // The items in each case are as following:
            // - client enable_multipath, client cid_len,
            // - server enable_multipath, server cid_len,
            // - multipath negotiation result
            (true, 8, false, 8, false),
            (false, 8, false, 8, false),
            (false, 8, true, 8, false),
            (true, 8, true, 8, true),
            (true, 0, true, 8, false),
            (true, 8, true, 0, false),
        ];
        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_multipath(case.0);
            client_config.set_cid_len(case.1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_multipath(case.2);
            server_config.set_cid_len(case.3);

            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));
            assert_eq!(test_pair.client.is_multipath(), case.4);
            assert_eq!(test_pair.server.is_multipath(), case.4);
        }

        Ok(())
    }

    #[test]
    fn handshake_with_disable_encryption_negotiated() -> Result<()> {
        let cases = [
            // The items in each case are as following:
            // - client disable_encryption
            // - server disable_encryption
            // - disable_encryption negotiation result
            //(true, false, false),
            //(false,false, false),
            //(false, true, false),
            (true, true, true),
        ];
        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_encryption(!case.0);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_encryption(!case.1);

            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));
            assert_eq!(test_pair.client.flags.contains(DisableEncryption), case.2);
            assert_eq!(test_pair.server.flags.contains(DisableEncryption), case.2);
        }

        Ok(())
    }

    #[test]
    fn max_datagram_size() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_send_udp_payload_size(1200);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_recv_udp_payload_size(1550);
        server_config.set_initial_max_data(10000);
        server_config.set_initial_max_stream_data_bidi_remote(10000);
        server_config.set_ack_eliciting_threshold(1);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(
            test_pair.client.paths.get(0)?.recovery.max_datagram_size,
            1200,
        );

        // Handshake and discovery path MTU
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        // Check path MTU
        let mds_ipv4 = 1472;
        assert_eq!(
            test_pair.client.paths.get(0)?.recovery.max_datagram_size,
            mds_ipv4
        );

        // Check outgoing packet size
        let mut buf = vec![0; 2000];
        assert!(test_pair
            .client
            .stream_write(0, Bytes::from(vec![0; 2000]), true)
            .is_ok());
        let r = test_pair.client.send(&mut buf);
        assert!(r.is_ok());
        assert_eq!(r.unwrap().0, mds_ipv4);

        Ok(())
    }

    #[test]
    fn transport_params() -> Result<()> {
        let server_trans_params = TransportParams {
            max_idle_timeout: 15000,
            initial_max_data: 1024000,
            ..TransportParams::default()
        };

        // Client perform the first handshake
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_trans_params.clone();

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        assert_eq!(
            test_pair.client.peer_transport_params.max_idle_timeout,
            server_trans_params.max_idle_timeout
        );
        assert_eq!(
            test_pair.client.peer_transport_params.initial_max_data,
            server_trans_params.initial_max_data
        );

        // Client perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;
        assert_eq!(
            test_pair.client.peer_transport_params.max_idle_timeout,
            server_trans_params.max_idle_timeout
        );
        assert_eq!(
            test_pair.client.peer_transport_params.initial_max_data,
            server_trans_params.initial_max_data
        );
        assert_eq!(test_pair.handshake(), Ok(()));

        Ok(())
    }

    #[test]
    fn cid_advertise_and_retire() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.client.set_index(0);
        test_pair.server.set_index(0);
        test_pair.handshake()?;

        // Client add a new cid
        let (scid, reset_token) = (ConnectionId::random(), 1);
        test_pair.client.add_scid(scid, reset_token, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 0);

        // Client send NEW_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        // Client add another cid
        let (scid, reset_token) = (ConnectionId::random(), 2);
        test_pair.client.add_scid(scid, reset_token, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 2);

        // Client send NEW_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 2);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1); // exceed cid limit

        // Server send RETIRE_CONNECTION_ID
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        Ok(())
    }

    #[test]
    fn cid_add_exceed_limit() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client add a new cid
        test_pair.client.add_scid(ConnectionId::random(), 1, true)?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);

        // Client add more cid
        assert_eq!(
            test_pair.client.add_scid(ConnectionId::random(), 2, false),
            Err(Error::ConnectionIdLimitError)
        );

        Ok(())
    }

    #[test]
    fn cid_advertise_on_zero_cid_conn() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let frame = frame::Frame::NewConnectionId {
            seq_num: 1,
            retire_prior_to: 0,
            conn_id: ConnectionId::random(),
            reset_token: ResetToken(1_u128.to_be_bytes()),
        };
        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;

        let info = TestPair::new_test_packet_info(false);
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn cid_retire_on_zero_cid_conn() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let frame = frame::Frame::RetireConnectionId { seq_num: 1 };
        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;

        let info = TestPair::new_test_packet_info(false);
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn path_new_by_client() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.paths_iter().len(), 1);
        assert_eq!(test_pair.server.paths_iter().len(), 1);

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        // Client and server advertise new cids
        test_pair.advertise_new_cids()?;
        assert_eq!(test_pair.client.cids.unused_scids(), 1);
        assert_eq!(test_pair.client.cids.unused_dcids(), 1);
        assert_eq!(test_pair.server.cids.unused_scids(), 1);
        assert_eq!(test_pair.server.cids.unused_dcids(), 1);

        // Client try to add path again
        test_pair.client.add_path(client_addr, server_addr)?;
        assert_eq!(test_pair.client.paths_iter().len(), 2);
        assert_eq!(test_pair.server.paths_iter().len(), 1);
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Unknown
        );

        // Client send PATH_CHALLENGE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validating
        );

        // Server send PATH_RESPONSE/PATH_CHALLENGE
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(test_pair.server.paths_iter().len(), 2);
        assert_eq!(
            test_pair.server.get_path(server_addr, client_addr)?.state(),
            PathState::Validating
        );

        // Client recv PATH_RESPONSE/PATH_CHALLENGE
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validated
        );

        // Client send PATH_RESPONSE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.server.get_path(server_addr, client_addr)?.state(),
            PathState::Validated
        );

        Ok(())
    }

    #[test]
    fn path_new_duplicated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        assert_eq!(
            test_pair.client.add_path(client_addr, server_addr),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn path_new_with_zero_cid() -> Result<()> {
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);

        // Client try to add path the connection with non-zero cid
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.add_path(client_addr, server_addr), Ok(1));
        let path = test_pair.client.get_path(client_addr, server_addr)?;
        assert_eq!(path.dcid_seq, None);

        // Client try to add path on the connection with zero cid
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;
        assert_eq!(test_pair.client.add_path(client_addr, server_addr), Ok(1));

        Ok(())
    }

    #[test]
    fn path_new_by_server() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9443);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 444);

        // Server try to add path
        assert_eq!(
            test_pair.server.add_path(server_addr, client_addr),
            Err(Error::InvalidOperation("disallowed".into()))
        );
        Ok(())
    }

    #[test]
    fn path_chal_timer_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client and server advertise new cids.
        test_pair.advertise_new_cids()?;

        // Client try to add path.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.client.add_path(client_addr, server_addr)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Unknown
        );
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_none());

        // Client send PATH_CHALLENGE and start PathChallenge timer.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validating
        );
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_some());

        // Client recv PATH_RESPONSE and stop PathChallenge timer.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.get_path(client_addr, server_addr)?.state(),
            PathState::Validated
        );
        assert!(test_pair.client.timeout().is_some());
        assert!(test_pair.client.timers.get(Timer::PathChallenge).is_none());

        Ok(())
    }

    #[test]
    fn path_chal_with_packet_loss() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        // Client send and fake lost of PATH_CHALLENGE.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let pid = test_pair.client.add_path(client_addr, server_addr)? as usize;
        TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validating
        );

        // Advance ticks until PATH_CHALLENGE timeout.
        assert!(test_pair.client.timeout().is_some());
        let now = time::Instant::now() + time::Duration::from_millis(path::INITIAL_CHAL_TIMEOUT);
        test_pair.client.on_timeout(now);

        // Client send PATH_CHALLENGE again.
        assert!(test_pair
            .client
            .paths
            .get(pid)?
            .need_send_validation_frames(false));
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Client recv PATH_RESPONSE.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validated
        );

        Ok(())
    }

    #[test]
    fn path_chal_loss_and_failed() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        // Client send and fake lost of PATH_CHALLENGE.
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        let pid = test_pair.client.add_path(client_addr, server_addr)? as usize;
        TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(
            test_pair.client.paths.get(pid)?.state(),
            PathState::Validating
        );

        for i in 0..path::MAX_PROBING_TIMEOUTS {
            // Advance ticks until PATH_CHALLENGE timeout.
            assert!(test_pair.client.timeout().is_some());
            let now = test_pair.client.timers.get(Timer::PathChallenge).unwrap();
            test_pair.client.on_timeout(now);

            // Try to send PATH_CHALLENGE again.
            TestPair::conn_packets_out(&mut test_pair.client)?;
        }

        // Path validation finally failed.
        assert_eq!(test_pair.client.paths.get(pid)?.state(), PathState::Failed);

        Ok(())
    }

    #[test]
    fn path_active_all_failed() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;

        // Fake failing of all active path
        let path = test_pair.client.paths.get_mut(0)?;
        path.set_active(false);

        assert!(test_pair.client.scid().is_err());
        assert!(test_pair.client.dcid().is_err());

        Ok(())
    }

    #[test]
    fn path_anti_ampl_limit() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(path.anti_ampl_limit, 0);
        }

        // Client send Initial.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        let len_in: usize = packets.iter().map(|p| p.0.len()).sum();

        // Server recv Initial.
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(
                path.anti_ampl_limit,
                len_in * test_pair.server.paths.anti_ampl_factor
            );
        }

        // Server send Initial and Handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        let len_out: usize = packets.iter().map(|p| p.0.len()).sum();
        {
            let path = test_pair.server.paths.get_active().unwrap();
            assert_eq!(
                path.anti_ampl_limit,
                len_in * test_pair.server.paths.anti_ampl_factor - len_out
            );
        }

        Ok(())
    }

    #[test]
    fn path_mtu_discovery_max() -> Result<()> {
        let cases = [
            // (cli_enable_dplpmtud, srv_enable_dplpmtud, cli_mtu , srv_mtu)
            (false, false, 1200, 1200),
            (false, true, 1200, 1472),
            (true, false, 1472, 1200),
            (true, true, 1472, 1472),
        ];

        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_dplpmtud(case.0);
            client_config.set_ack_eliciting_threshold(1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_dplpmtud(case.1);
            server_config.set_ack_eliciting_threshold(1);
            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            assert_eq!(test_pair.handshake(), Ok(()));

            test_pair.move_forward()?;
            assert_eq!(
                test_pair.client.paths.get(0)?.recovery.max_datagram_size,
                case.2
            );
            assert_eq!(
                test_pair.server.paths.get(0)?.recovery.max_datagram_size,
                case.3
            );
        }

        Ok(())
    }

    #[test]
    fn path_mtu_discovery_lost() -> Result<()> {
        let cases = [
            // (router_mtu, searched_mtu)
            (1472, 1463),
            (1452, 1446),
            (1432, 1429),
            (1412, 1404),
            (1392, 1387),
            (1372, 1370),
        ];

        for case in cases {
            let mut client_config = TestPair::new_test_config(false)?;
            client_config.enable_dplpmtud(true);
            client_config.set_ack_eliciting_threshold(1);
            let mut server_config = TestPair::new_test_config(true)?;
            server_config.enable_dplpmtud(false);
            server_config.set_initial_max_data(10240);
            server_config.set_initial_max_stream_data_bidi_remote(10240);
            server_config.set_ack_eliciting_threshold(1);
            let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
            let router_mtu: usize = case.0;

            // Handshake
            while !test_pair.client.is_established() || !test_pair.server.is_established() {
                let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
                packets.retain(|p| p.0.len() < router_mtu); // fake dropping packets
                TestPair::conn_packets_in(&mut test_pair.server, packets)?;

                let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
                TestPair::conn_packets_in(&mut test_pair.client, packets)?;
            }

            // Path MTU searching
            let data = Bytes::from_static(b"data");
            for i in 0..30 {
                let _ = test_pair.client.stream_write(0, data.clone(), false);
                let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
                packets.retain(|p| p.0.len() < router_mtu); // fake dropping packets

                TestPair::conn_packets_in(&mut test_pair.server, packets)?;
                let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
                TestPair::conn_packets_in(&mut test_pair.client, packets)?;

                if test_pair.client.timeout().is_some() {
                    let timeout = test_pair.client.timers.get(Timer::LossDetection);
                    test_pair.client.on_timeout(timeout.unwrap());
                }
            }

            // Check final MTU
            assert_eq!(
                test_pair.client.paths.get(0)?.recovery.max_datagram_size,
                case.1
            );
        }

        Ok(())
    }

    #[test]
    #[cfg(feature = "qlog")]
    fn ping() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        client_config.local_transport_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.enable_dplpmtud(false);
        server_config.local_transport_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;

        // Move both connections to idle state
        test_pair.move_forward()?;

        // Enable qlog for Server
        let slog = NamedTempFile::new().unwrap();
        let mut sfile = slog.reopen().unwrap();
        test_pair
            .server
            .set_qlog(Box::new(slog), "title".into(), "desc".into());

        // Client send a Ping frame
        test_pair.client.ping(None)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;

        let mut slog_content = String::new();
        sfile.read_to_string(&mut slog_content).unwrap();
        assert_eq!(slog_content.contains("quic:packet_received"), true);
        assert_eq!(slog_content.contains("frame_type\":\"ping"), true);

        Ok(())
    }

    #[test]
    fn conn_basic_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_zero_cid()?;
        test_pair.handshake()?;

        assert!(test_pair.client.trace_id().contains("CLIENT"));
        assert!(test_pair.server.trace_id().contains("SERVER"));

        assert!(test_pair.client.stats().recv_count > 0);
        assert!(test_pair.client.stats().sent_count > 0);

        assert!(test_pair.client.context().is_none());
        let cli_ctx = String::from("client context");
        test_pair.client.set_context(cli_ctx);
        assert!(test_pair.client.context().is_some());

        let ctx = test_pair.client.context().unwrap();
        let ctx = ctx.downcast_ref::<String>().unwrap();
        assert_eq!(ctx, "client context");

        assert!(test_pair.client.stream_context(0).is_none());
        let stream_ctx = String::from("client stream context");
        test_pair.client.stream_set_context(0, stream_ctx)?;
        assert!(test_pair.client.stream_context(0).is_some());

        let ctx = test_pair.client.stream_context(0).unwrap();
        let ctx = ctx.downcast_ref::<String>().unwrap();
        assert_eq!(ctx, "client stream context");

        Ok(())
    }

    #[test]
    fn recv_packet_empty_buffer() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Ignore the empty packet
        assert_eq!(test_pair.server.recv(&mut [], &info), Err(Error::NoError));
        assert_eq!(
            test_pair.server.recv_packet(&mut [], &info, None),
            Err(Error::Done)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_addr() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Server send NEW_CONNECTION_ID
        let (scid, reset_token) = (ConnectionId::random(), Some(1));
        test_pair
            .server
            .cids
            .add_scid(scid, reset_token, true, None, true)?;
        let mut packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert!(!packets.is_empty());

        // Change the packet address
        let (mut packet, mut info) = packets.pop().unwrap();
        info.src = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 10, 10, 10)), 443);

        // Client drop the packet with unknown address
        test_pair.client.recv(&mut packet, &info)?;
        Ok(())
    }

    #[test]
    fn recv_packet_empty_payload() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let mut packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[])?;
        let info = TestPair::new_test_packet_info(false);

        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_duplicated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv Initial
        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;

        // Server recv duplicated Initial
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Version field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut version = &mut initial_pkt[1..5]; // version field
        version.write_u32(0x1a1a1a1a)?;

        // Server recv Initial packet with unknown version
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Err(Error::UnknownVersion)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unmatched_version() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send Initial/Handshake packet
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send Handshake
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Version field of the Handshake packet
        let initial_pkt = &mut packets[0].0;
        let mut version = &mut initial_pkt[1..5]; // version field
        version.write_u32(0xbabababa)?;

        // Server drop the packet with unmatched version
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_too_big() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut len = &mut initial_pkt[48..50]; // length field
        len.write_varint_with_len(10000 as u64, 2)?;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_too_small() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        let mut len = &mut initial_pkt[48..50]; // length field
        len.write_varint_with_len(1 as u64, 2)?;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_length_variant_error() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial.
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Tamper Length field of the Initial packet
        let initial_pkt = &mut packets[0].0;
        initial_pkt[48] = 0;
        initial_pkt[49] = 0;

        // Server drop Initial packet with invalid length
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_truncated() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        let info = TestPair::new_test_packet_info(false);

        // Client send Initial packet
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(packets.len() > 0);

        // Truncate the Initial packet
        let (mut initial_pkt, info) = packets.pop().unwrap();
        initial_pkt.truncate(100);

        // Server drop the truncated packet
        assert_eq!(
            test_pair.server.recv_packet(&mut initial_pkt, &info, None),
            Err(Error::Done)
        );
        assert_eq!(
            test_pair.server.recv(&mut initial_pkt, &info),
            Ok(initial_pkt.len())
        );
        Ok(())
    }

    #[test]
    fn recv_packet_invalid_handshake_done() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut packet = TestPair::conn_build_packet(
            &mut test_pair.client,
            PacketType::OneRTT,
            &[frame::Frame::HandshakeDone],
        )?;
        let info = TestPair::new_test_packet_info(false);

        // Server recv HANDSHAKE_DONE
        assert_eq!(
            test_pair.server.recv(&mut packet, &info),
            Err(Error::ProtocolViolation)
        );
        Ok(())
    }

    #[test]
    fn recv_packet_unknown_dcid() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client send NEW_CONNECTION_ID
        let (scid, reset_token) = (ConnectionId::random(), Some(1));
        test_pair
            .server
            .cids
            .add_scid(scid, reset_token, true, None, true)?;
        let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert!(!packets.is_empty());

        // Tamper dcid field of the OneRTT packet
        let (mut packet, info) = packets.pop().unwrap();
        packet[1] = packet[1].wrapping_add(1); // change first byte of dcid field

        // Server drop the packet with unknown dcid
        assert!(test_pair.server.recv(&mut packet, &info).is_ok());
        Ok(())
    }

    #[test]
    fn recv_packet_stream_frame() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send OneRTT packet
        let content = "client one rtt data";
        let frame = TestPair::new_test_stream_frame(content.as_bytes());
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;
        let info = TestPair::new_test_packet_info(false);

        // Server recv OneRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
        assert!(test_pair.server.streams.has_readable_streams());

        let stream = test_pair.server.streams.get_mut(0).unwrap();
        assert!(stream.is_readable());

        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (content.len(), false));
        assert_eq!(content.as_bytes(), &buf[..content.len()]);
        Ok(())
    }

    #[test]
    fn recv_packet_skipped_packet_number() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let info = TestPair::new_test_packet_info(false);
        for i in 0..crate::MAX_ACK_RANGES + 10 {
            // Inject OneRTT packet with skipped packet number
            let space = test_pair.client.spaces.get_mut(SpaceId::Data).unwrap();
            space.next_pkt_num += 1;
            let packet = TestPair::conn_build_packet(
                &mut test_pair.client,
                PacketType::OneRTT,
                &[frame::Frame::Ping { pmtu_probe: None }],
            )?;

            // Server recv OneRTT packet and send ack
            TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)])?;
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;

            let space = &test_pair.server.spaces.get(SpaceId::Data).unwrap();
            let ranges_expected = if i < crate::MAX_ACK_RANGES {
                i + 1
            } else {
                crate::MAX_ACK_RANGES
            };
            assert_eq!(space.recv_pkt_num_need_ack.len(), ranges_expected);
        }
        Ok(())
    }

    #[test]
    fn send_packet_consecutive_non_ack_eliciting() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let info = TestPair::new_test_packet_info(false);
        for i in 0..space::MAX_NON_ACK_ELICITING + 10 {
            // Client send OneRTT packet
            let mut packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            let space = test_pair.client.spaces.get_mut(SpaceId::Data).unwrap();
            space.next_pkt_num += 1;
            packets.push((
                TestPair::conn_build_packet(
                    &mut test_pair.client,
                    PacketType::OneRTT,
                    &[frame::Frame::Ping { pmtu_probe: None }],
                )?,
                info,
            ));

            // Server recv OneRTT packet
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;

            // Server send ack packet with occasional PING to elicit ack
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;

            let space = test_pair.server.spaces.get(SpaceId::Data).unwrap();
            assert!(space.consecutive_non_ack_eliciting_sent <= space::MAX_NON_ACK_ELICITING);
        }

        Ok(())
    }

    #[test]
    fn ack_initial_or_handshake_space() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(2);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(2);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        // Client send 1 UDP datagram carrying 1 Initial packet
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(packets.len(), 1);

        // Server send 2 UDP datagrams carrying 1 Initial packet and 2 Handshake packets
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(packets.len(), 2);

        // Client's Initial must be acknowledged immediately
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        {
            let stat = test_pair.client.paths.get_active_mut()?.stats();
            assert_eq!(stat.acked_count, 1);
        }

        // Client send Handshake and completes handshake.
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server's Initial/Handshake must be acknowledged immediately
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        {
            let stat = test_pair.server.paths.get_active_mut()?.stats();
            assert_eq!(stat.acked_count, 3);
        }

        Ok(())
    }

    #[test]
    fn ack_data_space_ack_eliciting_threshold() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(4);
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(4);
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        let data = Bytes::from_static(b"QUIC");
        let sid = test_pair.client.stream_bidi_new(0, false)?;
        let acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;

        for i in 0..4 {
            // Client write data on the stream
            test_pair.client.stream_write(sid, data.clone(), false)?;
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv packets from the client
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

            TestPair::conn_packets_in(&mut test_pair.client, packets)?;
            let new_acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;
            if i < 3 {
                assert_eq!(acked_pkts, new_acked_pkts);
            } else {
                assert_eq!(acked_pkts + 4, new_acked_pkts);
            }
        }

        Ok(())
    }

    #[test]
    fn ack_data_space_ack_timeout() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(4);
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(4);
        server_config.enable_dplpmtud(false);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));
        test_pair.move_forward()?;

        let data = Bytes::from_static(b"QUIC");
        let sid = test_pair.client.stream_bidi_new(0, false)?;
        let acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;

        // Client write data on the stream
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv packets from the client
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        assert_eq!(packets.len(), 0);

        // Advance server ticks until ack timeout
        assert!(test_pair.server.timeout().is_some());
        let ack_timeout = test_pair.server.timers.get(Timer::Ack);
        assert!(ack_timeout.is_some());
        let now = ack_timeout.unwrap();
        test_pair.server.on_timeout(now);

        // Server send ack
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        let new_acked_pkts = test_pair.client.paths.get_active_mut()?.stats().acked_count;
        assert_eq!(acked_pkts + 1, new_acked_pkts);

        Ok(())
    }

    #[test]
    fn conn_close_by_application() -> Result<()> {
        // Establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        let err = ConnectionError {
            is_app: true,
            error_code: 0x1,
            frame: None,
            reason: b"exit".to_vec(),
        };

        // Client close the connection
        test_pair.client.close(true, 0x1, "exit".as_bytes())?;
        assert!(test_pair.client.is_closing());
        assert_eq!(test_pair.client.local_error(), Some(&err));
        assert_eq!(test_pair.client.peer_error(), None);

        // Client try to close the connection again
        assert_eq!(test_pair.client.close(true, 0x2, &[]), Err(Error::Done));

        // Client send CONNECTION_CLOSE
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.server.is_closing(), false);
        assert_eq!(test_pair.server.is_draining(), false);

        // Server recv CONNECTION_CLOSE and enter DRAINING
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.is_draining(), true);
        assert_eq!(test_pair.server.local_error(), None);
        assert_eq!(test_pair.server.peer_error(), Some(&err));
        assert_eq!(test_pair.server.close(false, 0x3, &[]), Err(Error::Done));

        Ok(())
    }

    #[test]
    fn conn_close_by_transport() -> Result<()> {
        // Establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client close the connection
        test_pair.client.close(false, 0, "shutdown".as_bytes())?;
        assert!(test_pair.client.is_closing());
        assert_eq!(test_pair.client.close(false, 0, &[]), Err(Error::Done));

        // Client send CONNECTION_CLOSE and Server enter DRAINING
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        assert_eq!(test_pair.server.is_closing(), false);
        assert_eq!(test_pair.server.is_draining(), false);

        TestPair::conn_packets_in(&mut test_pair.server, packets.clone())?;
        assert_eq!(test_pair.server.is_draining(), true);

        // Server try to close the connection again
        assert_eq!(test_pair.server.close(false, 0, &[]), Err(Error::Done));

        // Connection in the draining state drop the incoming packets
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, packets),
            Ok(())
        );

        Ok(())
    }

    #[test]
    fn conn_idle_timeout() -> Result<()> {
        let client_trans_params = TransportParams {
            max_idle_timeout: 60000,
            ..TransportParams::default()
        };
        let server_trans_params = TransportParams {
            max_idle_timeout: 15000,
            ..TransportParams::default()
        };
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.local_transport_params = client_trans_params.clone();
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_trans_params.clone();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.client.timeout(), None);
        assert_eq!(test_pair.server.timeout(), None);

        // Client/Server establish a connection
        test_pair.handshake()?;

        assert!(test_pair.client.timeout().is_some());
        let client_idle_timeout = test_pair.client.timers.get(Timer::Idle);
        assert!(client_idle_timeout.is_some());

        assert!(test_pair.server.timeout().is_some());
        let server_idle_timeout = test_pair.server.timers.get(Timer::Idle);
        assert!(server_idle_timeout.is_some());

        // Advance server ticks until idle timeout
        let now = server_idle_timeout.unwrap();
        test_pair.server.on_timeout(now);
        assert!(test_pair.server.is_idle_timeout());
        assert!(test_pair.server.is_closed());

        // Advance client ticks until idle timeout
        let now = client_idle_timeout.unwrap();
        test_pair.client.on_timeout(now);
        assert!(test_pair.client.is_idle_timeout());
        assert!(test_pair.client.is_closed());

        Ok(())
    }

    #[test]
    fn conn_idle_timeout_without_active_paths() -> Result<()> {
        let trans_params = TransportParams {
            max_idle_timeout: 10000,
            ..TransportParams::default()
        };
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.local_transport_params = trans_params.clone();
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = trans_params.clone();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        // Client/Server establish a connection
        test_pair.handshake()?;

        // Fake failing of initial path
        let path = test_pair.client.paths.get_mut(0)?;
        path.set_active(false);

        assert!(test_pair.client.timeout().is_some());
        assert_eq!(
            test_pair.client.idle_timeout(),
            Some(time::Duration::from_millis(10000))
        );

        Ok(())
    }

    #[test]
    fn conn_draining_timeout() -> Result<()> {
        // Client/Server establish a connection
        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair.handshake()?;

        // Client close the connection and send CONNECTION_CLOSE
        test_pair.client.close(false, 0, "shutdown".as_bytes())?;
        assert!(test_pair.client.is_closing());

        // Server recv CONNECTION_CLOSE and enters DRAINING
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.is_draining(), true);

        assert!(test_pair.server.timeout().is_some());
        let draining_timeout = test_pair.server.timers.get(Timer::Draining);
        assert!(draining_timeout.is_some());

        // Advance ticks until draining timeout
        let now = draining_timeout.unwrap();

        // Server connection closed.
        test_pair.server.on_timeout(now);
        assert!(test_pair.server.is_closed());
        assert_eq!(test_pair.server.timeout(), None);

        Ok(())
    }

    #[test]
    fn stream_operations() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let data = Bytes::from_static(b"EverythingOverQUIC");
        let sid = 4;

        // Client create a stream
        test_pair.client.stream_new(sid, 0, false)?;
        test_pair.client.stream_set_priority(sid, 1, false)?;
        test_pair.client.stream_want_write(sid, true)?;
        test_pair.client.stream_want_read(sid, true)?;
        assert_eq!(test_pair.client.get_streams().len(), 1);
        assert_eq!(test_pair.client.stream_writable_iter().len(), 1);
        assert!(test_pair.client.stream_writable(sid, data.len())?);
        assert!(test_pair.client.stream_capacity(sid)? > 0);

        // Client write data on the stream
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), true),
            Ok(data.len())
        );

        // Client shutdown the stream
        test_pair.client.stream_shutdown(sid, Shutdown::Read, 0)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read data from the client-initiated stream
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.stream_readable_iter().len(), 1);
        assert!(test_pair.server.stream_readable(sid));

        let mut buf = vec![0; data.len()];
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf)?,
            (data.len(), true)
        );
        assert_eq!(&buf[..data.len()], &data[..]);
        assert!(test_pair.server.stream_finished(sid));

        // Server shutdown the stream
        assert_eq!(
            test_pair.server.stream_shutdown(sid, Shutdown::Read, 0),
            Err(Error::Done)
        );
        assert_eq!(
            test_pair.server.stream_shutdown(sid, Shutdown::Write, 0),
            Err(Error::Done)
        );

        Ok(())
    }

    #[test]
    fn stream_multiply_write_and_read() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        for (data, fin) in vec![
            (Bytes::from_static(b"Everything"), false),
            (Bytes::from_static(b"Over"), false),
            (Bytes::from_static(b"QUIC"), true),
        ] {
            // Client write and send data on stream 4
            let len = data.len();
            assert_eq!(test_pair.client.stream_write(4, data.clone(), fin), Ok(len));
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv and read data on stream 4
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            let mut buf = vec![0; 18];
            assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, fin));
            assert_eq!(&buf[..len], &data[..]);
        }

        Ok(())
    }

    #[test]
    fn stream_multiplex_write_and_read() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        let mut tests = vec![
            (0, Bytes::from_static(b"Everything"), true),
            (4, Bytes::from_static(b"Over"), true),
            (8, Bytes::from_static(b"QUIC"), true),
        ];

        // Client write data on each stream
        for (sid, data, fin) in &tests {
            let len = data.len();
            assert_eq!(
                test_pair.client.stream_write(*sid, data.clone(), *fin),
                Ok(len)
            );
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read data on each stream
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        tests.shuffle(&mut thread_rng());
        for (sid, data, fin) in &tests {
            let mut buf = vec![0; 18];
            let len = data.len();
            assert_eq!(test_pair.server.stream_read(*sid, &mut buf)?, (len, *fin));
            assert_eq!(&buf[..len], &data[..]);
        }

        Ok(())
    }

    #[test]
    fn stream_0rtt() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        let mut server_config = TestPair::new_test_config(true)?;

        // Client perform the first handshake
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client extract session state and try to perform the second handshake
        let session = test_pair.client.session().unwrap();
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.client.set_session(&session)?;

        // Client write data on the stream
        let data = Bytes::from_static(b"Zero RTT data");
        let sid = 0;
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false),
            Ok(data.len())
        );
        let packets2 = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv Initial/ZeroRTT packet
        TestPair::conn_packets_in(&mut test_pair.server, packets2)?;
        let stream = test_pair.server.streams.get_mut(sid).unwrap();
        let mut buf = vec![0; 128];
        assert_eq!(stream.recv.read(&mut buf)?, (data.len(), false));
        assert_eq!(&data, &buf[..data.len()]);

        Ok(())
    }

    #[test]
    fn stream_flow_control_update() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create a stream
        let sid = 0;
        test_pair.client.stream_set_priority(sid, 0, false)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 40);

        // Client send data on the stream
        let data = TestPair::new_test_data(30);
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false)?,
            data.len()
        );
        assert_eq!(test_pair.client.stream_capacity(sid)?, 10);

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server read data from the stream
        let mut buf = [0; 64];
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf)?,
            (data.len(), false)
        );

        // Server send MAX_STREAM_DATA
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 40);

        Ok(())
    }

    #[test]
    fn stream_flow_control_limit_error() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send a STREAM to the server
        let data = TestPair::new_test_data(41);
        let frame = TestPair::new_test_stream_frame(&data);
        let packet =
            TestPair::conn_build_packet(&mut test_pair.client, PacketType::OneRTT, &[frame])?;
        let info = TestPair::new_test_packet_info(false);

        // Server found FlowControlError
        assert_eq!(
            TestPair::conn_packets_in(&mut test_pair.server, vec![(packet, info)]),
            Err(Error::FlowControlError)
        );
        let ConnectionError { error_code, .. } = test_pair.server.local_error().unwrap();
        assert_eq!(*error_code, Error::FlowControlError.to_wire());

        Ok(())
    }

    #[test]
    fn conn_multi_incremental_streams_send_round_robin() -> Result<()> {
        let server_transport_params = TransportParams {
            initial_max_data: 20000,
            initial_max_stream_data_bidi_remote: 20000,
            initial_max_streams_bidi: 4,
            ..TransportParams::default()
        };

        let mut client_config = TestPair::new_test_config(false)?;
        client_config.enable_dplpmtud(false);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.local_transport_params = server_transport_params.clone();

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // 1. Client create four bidi streams [0, 4, 8, 12], and write data on them
        let data = TestPair::new_test_data(1000);
        for i in 0..4 {
            assert_eq!(
                test_pair.client.stream_write(i * 4, data.clone(), true)?,
                data.len()
            );
        }

        // 2. Try to send stream data in round-robin order
        let mut packets = Vec::new();
        for i in 0..4 {
            let mut out = vec![0u8; 1500];
            let info = match test_pair.client.send(&mut out) {
                Ok((written, info)) => {
                    out.truncate(written);
                    info
                }
                Err(e) => return Err(e),
            };
            packets.push((out, info));
        }

        // 3. Server recv stream data, all streams must be readable
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        for i in 0..4 {
            assert!(test_pair.server.stream_readable(i * 4));
        }

        Ok(())
    }

    #[test]
    fn conn_max_streams_bidi() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create bidi streams
        let data = TestPair::new_test_data(5);
        for _ in 0..3 {
            let sid = test_pair.client.stream_bidi_new(0, false)?;
            assert_eq!(
                test_pair.client.stream_write(sid, data.clone(), true)?,
                data.len()
            );
        }
        // Client fail to create more streams
        assert_eq!(
            test_pair.client.stream_bidi_new(0, false),
            Err(Error::StreamLimitError)
        );
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read and shutdown streams
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = [0; 64];
        for i in 0..3 {
            test_pair.server.stream_read(i * 4, &mut buf)?;
            test_pair
                .server
                .stream_shutdown(i * 4, Shutdown::Write, 0)?;
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv RESET_STREAM and send ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server send MAX_STREAMS
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client create more streams
        assert_eq!(
            test_pair.client.stream_write(16, data.clone(), true)?,
            data.len()
        );

        Ok(())
    }

    #[test]
    fn conn_max_streams_uni() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create uni streams
        let data = TestPair::new_test_data(5);
        for _ in 0..2 {
            let sid = test_pair.client.stream_uni_new(0, false)?;
            assert_eq!(
                test_pair.client.stream_write(sid, data.clone(), true)?,
                data.len()
            );
        }
        // Client fail to create more streams
        assert_eq!(
            test_pair.client.stream_uni_new(0, false),
            Err(Error::StreamLimitError)
        );
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server read streams and send MAX_STREAMS
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = [0; 64];
        for i in 0..2 {
            test_pair.server.stream_read(2 + i * 4, &mut buf)?;
        }
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv MAX_STREAMS
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client create more streams
        assert_eq!(
            test_pair.client.stream_write(10, data.clone(), true)?,
            data.len()
        );

        Ok(())
    }

    #[test]
    fn stream_data_blocked() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send data on the stream
        let (sid, data) = (0, TestPair::new_test_data(40));
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false)?,
            data.len()
        );
        assert_eq!(test_pair.client.stream_capacity(sid)?, 0);

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server recv STREAM and send ACK
        assert_eq!(test_pair.server.stream_readable(sid), true);
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(test_pair.client.stream_capacity(sid)?, 0);
        assert_eq!(
            test_pair.client.stream_write(sid, data.clone(), false),
            Err(Error::Done)
        );

        // client send STREAM_DATA_BLOCKED
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        Ok(())
    }

    #[test]
    fn conn_data_blocked() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client send data on the streams
        let data = TestPair::new_test_data(30);
        for i in 0..3 {
            assert_eq!(
                test_pair.client.stream_write(i * 4, data.clone(), false)?,
                data.len()
            );
        }

        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server recv STREAM and send ACK
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client reck ACK
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        for i in 0..3 {
            assert_eq!(test_pair.client.stream_writable(i * 4, 1)?, false)
        }

        // client send DATA_BLOCKED
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        Ok(())
    }

    #[test]
    fn stream_reset() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_ack_eliciting_threshold(1);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        assert_eq!(test_pair.handshake(), Ok(()));
        let mut buf = vec![0; 16];

        // Client send data on a stream
        let (sid, data) = (0, TestPair::new_test_data(10));
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server shutdown the stream (Read/Write)
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Read, 1)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Write, 2)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv STOP_SENDING/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert_eq!(
            test_pair.client.stream_writable(sid, 1),
            Err(Error::StreamStopped(1))
        );
        assert_eq!(test_pair.client.stream_readable(sid), true);
        assert_eq!(
            test_pair.client.stream_read(sid, &mut buf),
            Err(Error::StreamReset(2))
        );

        // Client send ACK/RESET_STREAM
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server recv ACK/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.streams.is_closed(sid), true);
        assert_eq!(test_pair.server.stream_readable(sid), false);
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf),
            Err(Error::StreamStateError)
        );

        Ok(())
    }

    #[test]
    fn stream_shutdown_abnormal() -> Result<()> {
        let mut test_pair = TestPair::new_with_test_config()?;
        assert_eq!(test_pair.handshake(), Ok(()));
        let mut buf = vec![0; 16];

        // Client send data on a stream
        let (sid, data) = (0, TestPair::new_test_data(10));
        test_pair.client.stream_write(sid, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server shutdown the stream (Read/Write)
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Read, 1)?;
        test_pair.server.stream_shutdown(sid, Shutdown::Write, 2)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;

        // Client recv STOP_SENDING/RESET_STREAM
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Client send ACK
        let mut ack_ranges = RangeSet::new(1);
        ack_ranges.insert(0..2);
        let frame = frame::Frame::Ack {
            ack_delay: 0,
            ack_ranges,
            ecn_counts: None,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], false)?;
        assert_eq!(test_pair.server.streams.is_closed(sid), false);

        // Client send RESET_STREAM
        let frame = frame::Frame::ResetStream {
            stream_id: 0,
            error_code: 1,
            final_size: 10,
        };
        test_pair.build_packet_and_send(PacketType::OneRTT, &[frame], false)?;

        // Server stream 0 should be closed now
        assert_eq!(test_pair.server.streams.is_closed(sid), true);
        assert_eq!(test_pair.server.stream_readable(sid), false);
        assert_eq!(
            test_pair.server.stream_read(sid, &mut buf),
            Err(Error::StreamStateError)
        );

        Ok(())
    }

    // Establish a multipath connection between the client and server and then
    // send data blocks from the client to the server.
    //
    // The size of data block in `blocks` should be less than 256.
    fn conn_multipath_transfer(test_pair: &mut TestPair, blocks: Vec<Bytes>) -> Result<()> {
        // Handshake with multipath enabled
        test_pair.handshake()?;
        assert!(test_pair.client.is_multipath());
        assert!(test_pair.server.is_multipath());

        // Client and server advertise new cids
        test_pair.advertise_new_cids()?;

        // Client try to add a new path
        assert_eq!(test_pair.client.paths_iter().count(), 1);
        assert_eq!(test_pair.server.paths_iter().count(), 1);
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        assert_eq!(test_pair.client.paths_iter().count(), 2);
        assert_eq!(test_pair.server.paths_iter().count(), 2);

        // Client send bytes over multipath
        let mut buf = vec![0; 2048];
        for data in blocks.iter() {
            // Client write and send data on stream 4
            let len = data.len();
            assert_eq!(
                test_pair.client.stream_write(4, data.clone(), false),
                Ok(len)
            );
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;

            // Server recv and read data on stream 4
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, false));
            assert_eq!(&buf[..len], &data[..]);

            // Server reply ack
            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        }

        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_minrtt() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::MinRtt);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        let mut blocks = vec![];
        for i in 0..1000 {
            blocks.push(Bytes::from_static(b"Everything over multipath"));
        }
        conn_multipath_transfer(&mut test_pair, blocks)?;
        // Note: The scheduling result is uncertain, so we only verify if the
        // transmission was successful.
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_redundant() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::Redundant);
        client_config.set_ack_eliciting_threshold(1);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);

        // Handshake with multipath enabled
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::Redundant);
        server_config.set_ack_eliciting_threshold(1);
        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        let blocks = vec![
            Bytes::from_static(b"Everything"),
            Bytes::from_static(b"Over"),
            Bytes::from_static(b"Multipath QUIC"),
        ];

        conn_multipath_transfer(&mut test_pair, blocks)?;

        for (i, path) in test_pair.server.paths.iter_mut() {
            let s = path.stats();
            assert!(s.sent_count > 3);
            assert!(s.recv_count > 3);
        }
        Ok(())
    }

    #[test]
    fn conn_multipath_transfer_roundrobin() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);
        client_config.set_ack_eliciting_threshold(1);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);
        server_config.set_ack_eliciting_threshold(1);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        let mut blocks = vec![];
        for i in 0..100 {
            blocks.push(Bytes::from_static(b"Everything over multipath"));
        }
        conn_multipath_transfer(&mut test_pair, blocks)?;

        for (i, path) in test_pair.server.paths.iter_mut() {
            let s = path.stats();
            assert!(s.sent_count > 50);
            assert!(s.recv_count > 50);
        }
        Ok(())
    }

    #[test]
    #[cfg(feature = "qlog")]
    fn conn_write_qlog() -> Result<()> {
        let clog = NamedTempFile::new().unwrap();
        let mut cfile = clog.reopen().unwrap();
        let slog = NamedTempFile::new().unwrap();
        let mut sfile = slog.reopen().unwrap();

        let mut test_pair = TestPair::new_with_test_config()?;
        test_pair
            .client
            .set_qlog(Box::new(clog), "title".into(), "desc".into());
        test_pair
            .server
            .set_qlog(Box::new(slog), "title".into(), "desc".into());
        assert_eq!(test_pair.handshake(), Ok(()));

        // Client create a stream and send data
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Client lost some packets
        test_pair.client.stream_write(0, data.clone(), false)?;
        let _ = TestPair::conn_packets_out(&mut test_pair.client)?;
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Server read data from the stream
        let mut buf = vec![0; data.len()];
        test_pair.server.stream_read(0, &mut buf)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // The dropped packets may be declared as lost based on the time threshold.
        // If not, advance ticks until loss timeout.
        if test_pair.client.timeout().is_some() {
            let timeout = test_pair.client.timers.get(Timer::LossDetection);
            test_pair.client.on_timeout(timeout.unwrap());
        }

        // Check client qlog
        let mut clog_content = String::new();
        cfile.read_to_string(&mut clog_content).unwrap();
        assert_eq!(clog_content.contains("client"), true);
        assert_eq!(clog_content.contains("quic:parameters_set"), true);
        assert_eq!(clog_content.contains("quic:stream_data_moved"), true);
        assert_eq!(clog_content.contains("quic:packet_sent"), true);
        assert_eq!(clog_content.contains("recovery:metrics_updated"), true);
        assert_eq!(clog_content.contains("recovery:packet_lost"), true);

        // Check server qlog
        let mut slog_content = String::new();
        sfile.read_to_string(&mut slog_content).unwrap();
        assert_eq!(slog_content.contains("server"), true);
        assert_eq!(slog_content.contains("quic:parameters_set"), true);
        assert_eq!(slog_content.contains("quic:stream_data_moved"), true);
        assert_eq!(slog_content.contains("quic:packet_received"), true);
        assert_eq!(slog_content.contains("recovery:metrics_updated"), true);

        Ok(())
    }

    fn test_pair_for_key_update() -> Result<TestPair> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.set_initial_max_data(10000);
        client_config.set_initial_max_stream_data_bidi_local(10000);
        client_config.set_initial_max_stream_data_bidi_remote(10000);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.set_initial_max_data(10000);
        server_config.set_initial_max_stream_data_bidi_local(10000);
        server_config.set_initial_max_stream_data_bidi_remote(10000);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        assert_eq!(test_pair.handshake(), Ok(()));

        // Transfer some data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (19, false));
        assert_eq!(&buf[..19], &data[..]);

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(!test_pair.client.tls_session.current_key_phase());
        assert!(!test_pair.server.tls_session.current_key_phase());

        Ok(test_pair)
    }

    #[test]
    fn key_update() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(std::iter::once(space))?;

        // Transfer some data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (19, false));
        assert_eq!(&buf[..19], &data[..]);

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_packet_reorder() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client send data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let prev_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(std::iter::once(space))?;

        // Client send with new key.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), true)?;
        let new_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server receive reordered packets.
        TestPair::conn_packets_in(&mut test_pair.server, new_key_packets)?;
        TestPair::conn_packets_in(&mut test_pair.server, prev_key_packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf)?, (38, true));

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_previous_key_discard() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client send data.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), false)?;
        let prev_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(std::iter::once(space))?;
        // Client send with new key.
        let data = Bytes::from_static(b"test data over quic");
        test_pair.client.stream_write(0, data.clone(), true)?;
        let new_key_packets = TestPair::conn_packets_out(&mut test_pair.client)?;

        // Server discard previous key and receive reordered packets.
        TestPair::conn_packets_in(&mut test_pair.server, new_key_packets)?;

        let timeout = test_pair.server.timers.get(Timer::KeyDiscard);
        test_pair.server.on_timeout(timeout.unwrap());

        TestPair::conn_packets_in(&mut test_pair.server, prev_key_packets)?;
        let mut buf = vec![0; 2048];
        assert_eq!(test_pair.server.stream_read(0, &mut buf), Err(Error::Done));

        // Server reply ack.
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        assert!(test_pair.client.tls_session.current_key_phase());
        assert!(test_pair.server.tls_session.current_key_phase());

        Ok(())
    }

    #[test]
    fn key_update_with_consecutive_update() -> Result<()> {
        let mut test_pair = test_pair_for_key_update()?;

        // Client init key update.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        test_pair
            .client
            .tls_session
            .initiate_key_update(std::iter::once(space))?;

        // Client init another key update - should fail since no packet with new key phase
        // has been acknowledged yet.
        let space = test_pair
            .client
            .spaces
            .get_mut(SpaceId::Data)
            .ok_or(Error::InternalError)?;
        assert_eq!(
            test_pair
                .client
                .tls_session
                .initiate_key_update(std::iter::once(space)),
            Err(Error::Done)
        );

        Ok(())
    }

    #[test]
    fn multipath_secondary_path_inherits_max_ack_delay() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        client_config.enable_multipath(true);
        client_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);

        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);
        server_config.enable_multipath(true);
        server_config.set_multipath_algorithm(MultipathAlgorithm::RoundRobin);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;

        // Handshake — peer transport params with max_ack_delay=25ms are exchanged
        test_pair.handshake()?;
        assert!(test_pair.client.is_multipath());
        assert!(test_pair.server.is_multipath());

        // Advertise new CIDs and add second path
        test_pair.advertise_new_cids()?;
        let client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9444);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.add_and_validate_path(client_addr, server_addr)?;
        assert_eq!(test_pair.client.paths_iter().count(), 2);
        assert_eq!(test_pair.server.paths_iter().count(), 2);

        // Transfer data over multipath so both paths get RTT samples
        let mut buf = vec![0; 2048];
        for _ in 0..50 {
            let data = Bytes::from_static(b"test data over multipath");
            let len = data.len();
            assert_eq!(
                test_pair.client.stream_write(4, data.clone(), false),
                Ok(len)
            );
            let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
            TestPair::conn_packets_in(&mut test_pair.server, packets)?;
            assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, false));

            let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
            TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        }

        // Verify both paths on the server have reasonable RTT stats.
        // If max_ack_delay were not inherited (defaulting to 0), secondary path
        // srtt would be inflated because no ack_delay subtraction occurs.
        let mut path_srtts = vec![];
        for (_i, path) in test_pair.server.paths.iter_mut() {
            let s = path.stats();
            // Both paths should have sent/received data
            assert!(s.sent_count > 0, "path should have sent packets");
            assert!(s.recv_count > 0, "path should have received packets");
            if s.srtt > 0 {
                path_srtts.push(s.srtt);
            }
        }

        // With proper max_ack_delay inheritance, all path srtts should be
        // in the same order of magnitude (test environment has near-zero latency)
        if path_srtts.len() >= 2 {
            let max_srtt = *path_srtts.iter().max().unwrap();
            let min_srtt = *path_srtts.iter().min().unwrap();
            // In a loopback test, RTTs are very small. The key assertion is
            // that the secondary path's srtt is not wildly inflated.
            // With max_ack_delay=0 bug, secondary path srtt could be 10x+ higher.
            assert!(
                max_srtt < min_srtt * 100,
                "secondary path srtt ({max_srtt}us) should not be wildly inflated \
                 compared to primary ({min_srtt}us) — indicates max_ack_delay not inherited"
            );
        }

        Ok(())
    }

    #[test]
    fn migrate_path_preserves_connection() -> Result<()> {
        let mut client_config = TestPair::new_test_config(false)?;
        client_config.set_cid_len(crate::MAX_CID_LEN);
        let mut server_config = TestPair::new_test_config(true)?;
        server_config.set_cid_len(crate::MAX_CID_LEN);

        let mut test_pair = TestPair::new(&mut client_config, &mut server_config)?;
        test_pair.handshake()?;

        // Advertise new CIDs so migration has a dcid available
        test_pair.advertise_new_cids()?;

        // Add a new path from a different client address
        let new_client_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9445);
        let server_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 443);
        test_pair.client.add_path(new_client_addr, server_addr)?;

        // Exchange PATH_CHALLENGE / PATH_RESPONSE to validate path
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;

        // Migrate to the new path
        test_pair
            .client
            .migrate_path(new_client_addr, server_addr)?;

        // Verify connection still works — send and receive data on migrated path
        let mut buf = vec![0; 2048];
        let data = Bytes::from_static(b"data after migration");
        let len = data.len();
        assert_eq!(
            test_pair.client.stream_write(4, data.clone(), false),
            Ok(len)
        );
        let packets = TestPair::conn_packets_out(&mut test_pair.client)?;
        TestPair::conn_packets_in(&mut test_pair.server, packets)?;
        assert_eq!(test_pair.server.stream_read(4, &mut buf)?, (len, false));
        assert_eq!(&buf[..len], b"data after migration");

        // Server replies — verify bidirectional communication
        let packets = TestPair::conn_packets_out(&mut test_pair.server)?;
        TestPair::conn_packets_in(&mut test_pair.client, packets)?;

        // Verify path stats exist for the new path
        let stats = test_pair
            .client
            .get_path_stats(new_client_addr, server_addr)?;
        assert!(
            stats.sent_count > 0,
            "migrated path should have sent packets"
        );

        Ok(())
    }
