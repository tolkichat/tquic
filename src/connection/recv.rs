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

//! Inbound packet processing for QUIC connections.

use super::*;

use crate::shared_borrow_mut;

impl Connection {
    /// Process an incoming UDP datagram from the peer.
    ///
    /// On success the number of bytes processed is returned. On error the
    /// connection will be closed with an error code.
    #[doc(hidden)]
    pub fn recv(&mut self, buf: &mut [u8], info: &PacketInfo) -> Result<usize> {
        let len = buf.len();
        if len == 0 {
            return Err(Error::NoError);
        }

        // Check path of incoming datagram
        let pid = self.paths.get_path_id(&(info.dst, info.src)); // (local, remote)
        if pid.is_none() && !self.is_server {
            // If a client receives packets from an unknown address, it
            // discards these invalid packets.
            trace!(
                "{} client drop packet with unknown addr {:?}",
                self.trace_id,
                info
            );
            return Ok(len);
        }
        if let Some(pid) = pid {
            // Update send limit before address validation for server
            self.paths.inc_anti_ampl_limit(pid, len);
        }

        // Process each QUIC packet in the UDP datagram
        let mut left = len;
        while left > 0 {
            let read = match self.recv_packet(&mut buf[(len - left)..len], info, pid) {
                Ok(s) => s,
                Err(Error::Done) => left, // stop and skip the remaining data
                Err(e) => {
                    self.close(false, e.to_wire(), b"").ok(); // close connection
                    info!("{} recv error and close {:?}", self.trace_id, e);
                    return Err(e);
                }
            };
            left -= read;
        }

        // Try to process undecryptable packets
        if !self.is_established() {
            self.try_process_undecryptable_packets();
        }

        Ok(len - left)
    }

    /// Process an incoming QUIC packet from the peer.
    pub(super) fn recv_packet(
        &mut self,
        buf: &mut [u8],
        info: &PacketInfo,
        pid: Option<usize>,
    ) -> Result<usize> {
        if buf.is_empty() {
            return Err(Error::Done);
        }
        let now = time::Instant::now();

        // Check close status of connection
        if self.is_closing() || self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        // Parse header of the QUIC packet
        let (mut hdr, mut read) =
            PacketHeader::from_bytes(buf, self.scid()?.len()).map_err(|_| Error::Done)?;

        // Process Version Negotiation packet
        if hdr.pkt_type == PacketType::VersionNegotiation {
            return self.process_version_negotiation(&hdr, &buf[read..], info.time);
        }

        // Process Retry packet
        if hdr.pkt_type == PacketType::Retry {
            return self.process_retry(&hdr, buf, info.time);
        }

        // Check version of packet
        if self.is_server && !self.flags.contains(DidVersionNegotiation) {
            if !crate::version_is_supported(hdr.version) {
                return Err(Error::UnknownVersion);
            }
            self.version = hdr.version;
            self.flags.insert(DidVersionNegotiation);
        }
        if hdr.pkt_type != PacketType::OneRTT && hdr.version != self.version {
            return Err(Error::Done);
        }

        // Create new path if need.
        let pid = if hdr.pkt_type == PacketType::OneRTT && self.flags.contains(HandshakeCompleted) {
            self.get_or_create_path(pid, &hdr.dcid, info, buf.len())?
        } else {
            // Use the initial path during handshake.
            self.paths.get_active_path_id()?
        };

        // Get length of packet number field and packet payload
        let length = if hdr.pkt_type == PacketType::OneRTT {
            // A packet with a short header does not include a length field, so it
            // can only be the last packet included in a UDP datagram.
            buf.len() - read
        } else {
            let mut b = &buf[read..];
            let len = b.read_varint().map_err(|_| Error::Done)?;
            read = buf.len() - b.len();
            // Make sure the length field is valid.
            if len > b.len() as u64 {
                return Err(Error::Done);
            }
            len as usize
        };
        let pkt_num_offset = read;

        // Derive initial secrets for the server
        if !self.flags.contains(DerivedInitialSecrets) {
            self.tls_session
                .derive_initial_secrets(&hdr.dcid, self.version)?;
            self.flags.insert(DerivedInitialSecrets);
        }

        // Decrypt packet header
        let key = self.tls_session.get_keys(hdr.pkt_type.to_level()?);
        let key = match &key.open {
            Some(open) => open,
            None => {
                let pkt = buf[..read + length].to_vec();
                self.try_buffer_undecryptable_packets(&hdr, pkt, info);
                return Ok(read + length);
            }
        };
        let is_encryption_disabled = self.is_encryption_disabled(hdr.pkt_type);
        packet::decrypt_header(buf, pkt_num_offset, &mut hdr, key, is_encryption_disabled)
            .map_err(|_| Error::Done)?;

        // Decode packet sequence number
        let handshake_confirmed = self.is_confirmed();
        let space_id = self.get_space_id(hdr.pkt_type, pid)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        let largest_rx_pkt_num = space.largest_rx_pkt_num;
        let pkt_num = packet::decode_packet_num(largest_rx_pkt_num, hdr.pkt_num, hdr.pkt_num_len);

        if space.detect_duplicated_pkt_num(pkt_num) {
            trace!(
                "{} ignore duplicated packet {:?}:{}",
                self.trace_id,
                space_id,
                pkt_num
            );
            return Err(Error::Done);
        }

        // Select key and decrypt packet payload.
        let payload_offset = pkt_num_offset + hdr.pkt_num_len;
        let payload_len = length.checked_sub(hdr.pkt_num_len).ok_or(Error::Done)?;
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            let (seq, _) = self
                .cids
                .find_scid(&hdr.dcid)
                .ok_or(Error::InvalidState("unknown dcid".into()))?;
            cid_seq = Some(seq as u32)
        }

        let (key, attempt_key_update) =
            self.tls_session
                .select_key(handshake_confirmed, &hdr, space)?;
        let mut payload = if !is_encryption_disabled {
            packet::decrypt_payload(buf, payload_offset, payload_len, cid_seq, pkt_num, key)
                .map_err(|_| Error::Done)?
        } else {
            bytes::Bytes::copy_from_slice(&buf[payload_offset..payload_offset + payload_len])
        };
        if payload.is_empty() {
            // An endpoint MUST treat receipt of a packet containing no frames as a connection error
            // of type PROTOCOL_VIOLATION.
            return Err(Error::ProtocolViolation);
        }
        read += length;

        debug!(
            "{} recv packet {:?} pn={} {:?}",
            self.trace_id,
            hdr,
            pkt_num,
            self.paths.get(pid)?
        );

        // Try to update key.
        let key_updated = self.tls_session.try_update_key(
            &mut self.timers,
            space,
            attempt_key_update,
            &hdr,
            now,
            self.paths.max_pto(),
        )?;

        // In multipath mode, when a key update occurs, reset key phase tracking
        // in all other data spaces. This ensures all paths start fresh tracking
        // for the new key phase.
        if key_updated && self.flags.contains(EnableMultipath) {
            use crate::tls::TlsSession;
            for (_, other_space) in self.spaces.iter_mut() {
                if other_space.is_data && other_space.id != space_id {
                    TlsSession::reset_key_phase_tracking(other_space);
                }
            }
        }

        // Update dcid for initial path
        self.try_set_dcid_for_initial_path(pid, &hdr)?;

        // Process each QUIC frame in the QUIC packet
        let mut ack_eliciting_pkt = false;
        let mut probing_pkt = true;
        #[cfg(feature = "qlog")]
        let mut qframes = vec![];

        while !payload.is_empty() {
            let (frame, len) = Frame::from_bytes(&mut payload, hdr.pkt_type)?;
            if frame.ack_eliciting() {
                ack_eliciting_pkt = true;
            }
            if !frame.probing() {
                probing_pkt = false;
            }
            #[cfg(feature = "qlog")]
            if self.qlog.is_some() {
                qframes.push(frame.to_qlog());
            }

            self.recv_frame(frame, &hdr, pid, space_id, info.time)?;
            let _ = payload.split_to(len);
        }

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketReceived event to qlog.
            Self::qlog_quic_packet_received(qlog, &hdr, pkt_num, read, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(pid) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Process acknowledged frames.
        self.try_process_acked_frames();

        // The peer may issue new connection ids. If there is any path waiting
        // for a dcid, try to allocate one for it.
        self.try_allocate_cids_from_peer();

        // Update packet number space
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.recv_pkt_num_need_ack.max() < Some(pkt_num) {
            space.largest_rx_pkt_time = info.time;
        }
        space.recv_pkt_num_win.insert(pkt_num);
        space.recv_pkt_num_need_ack.add_elem(pkt_num);
        space.largest_rx_pkt_num = cmp::max(space.largest_rx_pkt_num, pkt_num);
        if !probing_pkt {
            space.largest_rx_non_probing_pkt_num =
                cmp::max(space.largest_rx_non_probing_pkt_num, pkt_num);
            // TODO: try to do connection migration
        }
        if ack_eliciting_pkt {
            space.largest_rx_ack_eliciting_pkt_num =
                cmp::max(space.largest_rx_ack_eliciting_pkt_num, pkt_num);
        }

        self.try_schedule_ack_frame(space_id, pkt_num, ack_eliciting_pkt)?;

        // An endpoint restarts its idle timer when a packet from its peer is
        // received and processed successfully.
        // See RFC 9000 Section 10.1
        if let Some(idle_timeout) = self.idle_timeout() {
            self.timers.set(Timer::Idle, now + idle_timeout);
        }

        // Update statistic metrics
        self.stats.recv_count += 1;
        self.stats.recv_bytes += read as u64;
        self.paths
            .get_mut(pid)?
            .recovery
            .stat_recv_event(1, read as u64);

        // The successful use of Handshake packets indicates that no more
        // Initial packets need to be exchanged, as these keys can only be
        // produced after receiving all CRYPTO frames from Initial packets.
        // Thus, a server MUST discard Initial keys when it first successfully
        // processes a Handshake packet.
        // See RFC 9001 Section 4.9.3
        if self.is_server && hdr.pkt_type == PacketType::Handshake {
            self.drop_space_state(SpaceId::Initial, info.time);

            // Receipt of a packet protected with Handshake keys confirms that
            // the peer successfully processed an Initial packet. Once an
            // endpoint has successfully processed a Handshake packet from the
            // peer, it can consider the peer address to have been validated.
            // See RFC 9000 Section 8.1
            self.paths.get_mut(pid)?.verified_peer_address = true;
        }

        self.flags.insert(NeedSendAckEliciting);

        Ok(read)
    }

    /// Process an incoming QUIC frame from the peer.
    fn recv_frame(
        &mut self,
        frame: Frame,
        hdr: &PacketHeader,
        path_id: usize,
        space_id: SpaceId,
        now: time::Instant,
    ) -> Result<()> {
        debug!("{} recv frame {:?}", self.trace_id, &frame);
        match frame {
            Frame::Paddings { .. } => (), // just ignore

            Frame::Ping { .. } => (), // just ignore

            Frame::Ack {
                ack_delay,
                ack_ranges,
                ..
            } => {
                // ACK Delay is decoded by multiplying the value in the field
                // by 2 to the power of the ack_delay_exponent transport
                // parameter sent by the sender of the ACK frame.
                let mul = 2_u64.pow(self.peer_transport_params.ack_delay_exponent as u32);
                let ack_delay = ack_delay
                    .checked_mul(mul)
                    .ok_or(Error::FrameEncodingError)?;

                if space_id == SpaceId::Handshake {
                    self.flags.insert(PeerVerifiedInitialAddress);
                }
                if space_id == SpaceId::Data && self.is_established() {
                    self.flags.insert(PeerVerifiedInitialAddress);
                    // A client MAY consider the handshake to be confirmed when
                    // it receives an acknowledgment for a 1-RTT packet. This
                    // can be implemented by recording the lowest packet number
                    // sent with 1-RTT keys and comparing it to the Largest
                    // Acknowledged field in any received 1-RTT ACK frame
                    // See RFC 9001 Section 4.1.2
                    let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
                    if !self.is_server && ack_ranges.max() > Some(space.lowest_1rtt_pkt_num) {
                        self.flags.insert(HandshakeConfirmed);
                    }
                }

                // Process acknowledgement
                let handshake_status = self.handshake_status(self.paths.get(path_id)?);
                let path = self.paths.get_mut(path_id)?;
                let (lost_pkts, lost_bytes) = path.recovery.on_ack_received(
                    &ack_ranges,
                    ack_delay,
                    space_id,
                    &mut self.spaces,
                    handshake_status,
                    #[cfg(feature = "qlog")]
                    self.qlog.as_mut(),
                    now,
                )?;
                self.stats.lost_count += lost_pkts;
                self.stats.lost_bytes += lost_bytes;

                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                if self.flags.contains(HandshakeConfirmed) {
                    self.drop_space_state(SpaceId::Handshake, now);
                }
            }

            Frame::Crypto { offset, data, .. } => {
                let level = space_id.to_level();

                // Insert crypto data to the corresponding crypto stream.
                {
                    // Note: The crypto_streams is shared between the QUIC connection and
                    // the TLS session. It may be mutably borrowed during calling
                    // self.tls_session.read(). Do NOT mutably borrrow it again at the
                    // same scope.
                    let mut crypto_streams = shared_borrow_mut(&self.crypto_streams);
                    let crypto_stream = crypto_streams.get_mut(level)?;
                    crypto_stream.recv.write(offset, data, false)?;
                }

                // Read crypto data in order and feed it to the TLS session
                let mut crypto_buf = [0; 512];
                loop {
                    let read = {
                        let mut crypto_streams = shared_borrow_mut(&self.crypto_streams);
                        let crypto_stream = crypto_streams.get_mut(level)?;
                        match crypto_stream.recv.read(&mut crypto_buf) {
                            Ok((read, _)) => read,
                            _ => break,
                        }
                    };

                    let r = self.tls_session.provide(level, &crypto_buf[..read]);
                    self.process_tls_session(r)?;
                }
            }

            Frame::HandshakeDone => {
                if self.is_server {
                    return Err(Error::ProtocolViolation);
                }
                self.flags.insert(PeerVerifiedInitialAddress);
                self.flags.insert(HandshakeConfirmed);
                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                self.drop_space_state(SpaceId::Handshake, now);
            }

            Frame::NewConnectionId {
                seq_num,
                retire_prior_to,
                conn_id,
                reset_token,
            } => {
                if self.cids.zero_length_dcid() {
                    // An endpoint that is sending packets with a zero-length
                    // Destination CID MUST treat receipt of a NEW_CONNECTION_ID
                    // frame as a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Add a new dcid and retire the specified dcids
                let retired_dcids = self.cids.add_dcid(
                    conn_id,
                    seq_num,
                    u128::from_be_bytes(reset_token.0),
                    retire_prior_to,
                )?;
                self.events.add(Event::DcidAdvertised(reset_token));

                // Try to assign unused dcids to the affected paths
                for (dcid_seq, pid) in retired_dcids {
                    let path = self.paths.get_mut(pid)?;
                    if path.dcid_seq != Some(dcid_seq) {
                        continue;
                    }
                    if let Some(new_dcid_seq) = self.cids.lowest_unused_dcid_seq() {
                        path.dcid_seq = Some(new_dcid_seq);
                        self.cids.mark_dcid_used(new_dcid_seq, pid)?;
                    } else {
                        path.dcid_seq = None; // wait for a new DCID from peer
                    }
                }
            }

            Frame::RetireConnectionId { seq_num } => {
                if self.cids.zero_length_scid() {
                    // An endpoint that provides a zero-length connection ID
                    // MUST treat receipt of a RETIRE_CONNECTION_ID frame as
                    // a connection error of type PROTOCOL_VIOLATION.
                    return Err(Error::ProtocolViolation);
                }

                // Remove the connection route entry on the endpoint
                match self.cids.get_scid(seq_num) {
                    Ok(c) => self.events.add(Event::ScidRetired(c.cid)),
                    Err(_) => return Ok(()),
                };

                if let Some(pid) = self.cids.retire_scid(seq_num, &hdr.dcid)? {
                    let path = self.paths.get_mut(pid)?;
                    if path.scid_seq == Some(seq_num) {
                        path.scid_seq = None;
                    }
                }
            }

            Frame::PathChallenge { data } => {
                self.paths.on_path_chal_received(path_id, data);
            }

            Frame::PathResponse { data } => {
                if self.paths.on_path_resp_received(path_id, data) {
                    // Notify the path event to the multipath scheduler
                    if let Some(ref mut scheduler) = self.multipath_scheduler {
                        scheduler.on_path_updated(&mut self.paths, PathEvent::Validated(path_id));
                    }
                }
            }

            frame::Frame::PathAbandon {
                dcid_seq_num,
                error_code,
                reason,
            } => { // temparaily ignore
            }

            frame::Frame::PathStatus {
                dcid_seq_num,
                seq_num,
                status,
            } => { // temparaily ignore
            }

            Frame::NewToken { token } => {
                self.events.add(Event::NewToken(token));
            }

            // After receiving a CONNECTION_CLOSE frame, endpoints enter the
            // draining state. While otherwise identical to the closing state,
            // an endpoint in the draining state MUST NOT send any packets.
            Frame::ConnectionClose {
                error_code, reason, ..
            } => {
                self.peer_error = Some(ConnectionError {
                    is_app: false,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }
            Frame::ApplicationClose { error_code, reason } => {
                self.peer_error = Some(ConnectionError {
                    is_app: true,
                    frame: None,
                    error_code,
                    reason,
                });
                let pto = self.paths.get_active_mut()?.recovery.rtt.pto_base();
                self.timers.set(Timer::Draining, now + pto * 3);
            }

            Frame::Stream {
                stream_id,
                offset,
                length,
                fin,
                data,
            } => {
                self.streams
                    .on_stream_frame_received(stream_id, offset, length, fin, data)?;
            }

            Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            } => {
                self.streams
                    .on_reset_stream_frame_received(stream_id, error_code, final_size)?;
            }

            Frame::StopSending {
                stream_id,
                error_code,
            } => {
                self.streams
                    .on_stop_sending_frame_received(stream_id, error_code)?;
            }

            Frame::MaxData { max } => {
                self.streams.on_max_data_frame_received(max);
            }

            Frame::MaxStreamData { stream_id, max } => {
                self.streams
                    .on_max_stream_data_frame_received(stream_id, max)?;
            }

            Frame::MaxStreams { bidi, max } => {
                self.streams.on_max_streams_frame_received(max, bidi)?;
            }

            Frame::DataBlocked { max } => {
                self.streams.on_data_blocked_frame_received(max);
            }

            Frame::StreamDataBlocked { stream_id, max } => {
                self.streams
                    .on_stream_data_blocked_frame_received(stream_id, max)?;
            }

            Frame::StreamsBlocked { bidi, max } => {
                self.streams.on_streams_blocked_frame_received(max, bidi)?;
            }

            Frame::Datagram { data } => {
                // Check that we advertised datagram support
                if self
                    .local_transport_params
                    .max_datagram_frame_size
                    .is_none()
                {
                    return Err(Error::ProtocolViolation);
                }
                if self.dgram_recv_queue.len() < 128 {
                    self.dgram_recv_queue.push_back(data);
                    self.events.add(Event::DatagramReceived);
                }
            }
        }

        Ok(())
    }

    /// Process the incoming Version Negotiation packet.
    fn process_version_negotiation(
        &mut self,
        pkt_hdr: &PacketHeader,
        mut payload: &[u8],
        now: time::Instant,
    ) -> Result<usize> {
        // The Version Negotiation packet is a response to a client packet that
        // contains a version that is not supported by the server. It is only
        // sent by servers.
        if self.is_server {
            return Err(Error::Done);
        }

        if self.flags.contains(DidVersionNegotiation) {
            return Err(Error::Done);
        }

        // A client MUST discard any Version Negotiation packet if it has
        // received and successfully processed any other packet, including an
        // earlier Version Negotiation packet.
        if self.stats.recv_count > 0 {
            return Err(Error::Done);
        }

        // The sever must echo both CIDs gives clients some assurance that the
        // server received the packet and that the Version Negotiation packet
        // was not generated by an entity that did not observe the Initial packet.
        if pkt_hdr.dcid != self.scid()? {
            return Err(Error::Done);
        }
        if pkt_hdr.scid != self.dcid()? {
            return Err(Error::Done);
        }

        let mut found_version = 0;
        while !payload.is_empty() {
            let version = payload.read_u32().map_err(|_| Error::Done)?;
            if crate::version_is_supported(version) {
                found_version = cmp::max(found_version, version);
            }
        }

        if found_version == 0 {
            return Err(Error::UnknownVersion);
        }

        // A client MUST discard a Version Negotiation packet that lists the
        // QUIC version selected by the client.
        if found_version == self.version {
            return Err(Error::Done);
        }

        self.version = found_version;
        self.flags.insert(DidVersionNegotiation);
        self.flags.remove(GotPeerCid);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;
        self.set_transport_params()?;

        // Derive Initial secrets based on the new version.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Process the incoming RETRY packet.
    fn process_retry(
        &mut self,
        pkt_hdr: &PacketHeader,
        pkt_buf: &mut [u8],
        now: time::Instant,
    ) -> Result<usize> {
        // The Retry packet is only sent by the server to request address
        // validation upon receiving the client's Initial packet.
        if self.is_server {
            return Err(Error::Done);
        }

        // A client MUST accept and process at most one Retry packet for each
        // connection attempt. After the client has received and processed an
        // Initial or Retry packet from the server, it MUST discard any
        // subsequent Retry packets that it receives.
        if self.flags.contains(DidRetry) {
            return Err(Error::Done);
        }

        // Clients MUST discard Retry packets that have a Retry Integrity Tag
        // that cannot be validated. This diminishes an attacker's ability to
        // inject a Retry packet and protects against accidental corruption of
        // Retry packets.
        if packet::verify_retry_integrity_tag(pkt_buf, &self.dcid()?, self.version).is_err() {
            return Err(Error::Done);
        }

        self.token.clone_from(&pkt_hdr.token);
        self.flags.insert(DidRetry);
        self.flags.remove(GotPeerCid);

        // A client sets the Destination Connection ID field of this Initial
        // packet to the value from the Source Connection ID field in the Retry
        // packet.
        self.odcid = Some(self.dcid()?);
        self.set_initial_dcid(pkt_hdr.scid, None, self.paths.get_active_path_id()?)?;
        self.rscid = Some(self.dcid()?);

        // Reset connection state to force sending another Initial packet.
        self.drop_space_state(SpaceId::Initial, now);
        self.tls_session.clear()?;

        // Changing the Destination Connection ID field also results in a
        // change to the keys used to protect the Initial packet.
        self.tls_session
            .derive_initial_secrets(&self.dcid()?, self.version)?;
        self.tls_session.process()?;

        Err(Error::Done)
    }

    /// Check and record handshake status.
    fn process_tls_session(&mut self, tls_result: Result<()>) -> Result<()> {
        if self.flags.contains(HandshakeCompleted) {
            return tls_result;
        }

        match tls_result {
            Ok(_) => (),
            Err(Error::Done) => {
                // Try to parse transport parameters as soon as the first flight data is processed.
                let peer_params = self.tls_session.peer_transport_params();
                if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
                    let (peer_params, _) = TransportParams::decode(peer_params, self.is_server)?;
                    self.process_peer_trans_params(peer_params)?;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        }

        let peer_params = self.tls_session.peer_transport_params();
        if !self.flags.contains(AppliedPeerTransportParams) && !peer_params.is_empty() {
            let (peer_params, _) = TransportParams::decode(peer_params, self.is_server)?;
            self.process_peer_trans_params(peer_params)?;
        }

        if self.tls_session.is_completed() {
            self.flags.insert(HandshakeCompleted);
            self.events.add(Event::ConnectionEstablished);
            self.timers.stop(Timer::Handshake);
            self.try_process_undecryptable_packets();

            if self.is_server {
                // The TLS handshake is considered confirmed at the server when
                // the handshake completes. The server MUST send a HANDSHAKE_DONE
                // frame as soon as the handshake is complete.
                self.flags.insert(HandshakeConfirmed);
                self.flags.insert(NeedSendHandshakeDone);

                // An endpoint MUST discard its Handshake keys when the TLS
                // handshake is confirmed.
                self.drop_space_state(SpaceId::Handshake, time::Instant::now());
            }

            // Try to promote to multipath mode.
            if self.peer_transport_params.enable_multipath
                && self.local_transport_params.enable_multipath
            {
                // If an enable_multipath transport parameter is received and
                // the carrying packet contains a zero length connection ID,
                // the receiver MUST treat this as a connection error.
                if self.cids.zero_length_dcid() {
                    return Err(Error::MultipathProtocolViolation);
                }

                self.multipath_scheduler = Some(build_multipath_scheduler(&self.multipath_conf));
                self.paths.enable_multipath();
                self.flags.insert(EnableMultipath);
                debug!("{} enable multipath", &self.trace_id);
            }

            // Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
            self.try_schedule_control_frames();
        }

        Ok(())
    }

    /// Validate and apply transport parameters advertised by the peer.
    fn process_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        // Validate cid related transport parameters
        if peer_params.initial_source_connection_id != Some(self.dcid()?) {
            return Err(Error::TransportParameterError);
        }
        if !self.is_server {
            if peer_params.original_destination_connection_id != self.odcid {
                return Err(Error::TransportParameterError);
            }
            if peer_params.retry_source_connection_id != self.rscid {
                return Err(Error::TransportParameterError);
            }
        }

        // The remote server can issue a stateless_reset_token transport parameter
        // that applies to the connection ID that it selected during the handshake.
        if let Some(reset_token) = peer_params.stateless_reset_token {
            let reset_token = ResetToken::from_u128(reset_token);
            self.events.add(Event::ResetTokenAdvertised(reset_token));
        }

        // The connection enters disable_1rtt_encryption mode
        if peer_params.disable_encryption && self.local_transport_params.disable_encryption {
            self.flags.insert(DisableEncryption);
            debug!(
                "{} encryption on 1-RTT packets has been negotiated to be disabled",
                self.trace_id
            );
        }

        self.set_peer_trans_params(peer_params)?;
        self.flags.insert(AppliedPeerTransportParams);

        // Write TransportParametersSet event to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            Self::qlog_quic_params_set(
                qlog,
                &self.peer_transport_params,
                events::Owner::Remote,
                self.tls_session.cipher(),
            );
        }

        Ok(())
    }

    /// Set transport parameters advertised by the peer
    pub(super) fn set_peer_trans_params(&mut self, peer_params: TransportParams) -> Result<()> {
        trace!(
            "{} set peer transport parameters {:?}",
            self.trace_id,
            peer_params
        );

        self.streams
            .update_peer_stream_transport_params(stream::StreamTransportParams::from(&peer_params));

        let active_path = self.paths.get_active_mut()?;
        let max_ack_delay = time::Duration::from_millis(peer_params.max_ack_delay);
        active_path.recovery.max_ack_delay = max_ack_delay;

        // Propagate peer's max_ack_delay to recovery_conf so that new paths
        // created via add_path() (multipath) inherit the correct value.
        // Without this, secondary paths would have max_ack_delay=0, causing
        // the ack_delay cap (RFC 9000 §5.3) to zero out all ack_delay
        // subtraction and inflate their RTT estimates.
        self.recovery_conf.max_ack_delay = max_ack_delay;

        let max_datagram_size = peer_params.max_udp_payload_size as usize;
        active_path
            .recovery
            .update_max_datagram_size(max_datagram_size, true);

        self.cids.set_scid_limit(peer_params.active_conn_id_limit);

        self.peer_transport_params = peer_params;
        Ok(())
    }
}
