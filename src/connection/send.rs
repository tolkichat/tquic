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

//! Outbound packet construction for QUIC connections.

use super::*;

impl Connection {
    pub(crate) fn max_datagram_size(&self, pid: usize) -> usize {
        // The peer's `max_udp_payload_size` transport parameter limits the
        // size of UDP payloads that it is willing to receive. Therefore,
        // prior to receiving that parameter, we only use the default value.
        if !self.flags.contains(AppliedPeerTransportParams) {
            return crate::MIN_CLIENT_INITIAL_LEN;
        }

        // Use the validated max_datagram_size
        self.paths
            .get(pid)
            .ok()
            .map_or(crate::MIN_CLIENT_INITIAL_LEN, |path| {
                path.recovery.max_datagram_size
            })
    }

    /// Write coalesced multiple QUIC packets to the given buffer which will
    /// then be sent to the peer.
    ///
    /// The size of `out` should be at least 1200 bytes, ideally matching or
    /// exceeding the maximum possible MTU.
    ///
    /// Return Error::Done if no packet can be sent.
    pub(crate) fn send(&mut self, out: &mut [u8]) -> Result<(usize, PacketInfo)> {
        if out.len() < crate::MIN_CLIENT_INITIAL_LEN {
            return Err(Error::BufferTooShort);
        }

        // Check close status of connection
        if self.is_draining() || self.is_closed() {
            return Err(Error::Done);
        }

        if !self.flags.contains(DerivedInitialSecrets) {
            return Err(Error::Done);
        }

        if !self.is_server && !self.flags.contains(InitiatedClientHandshake) {
            match self.tls_session.process() {
                Ok(_) => {}
                Err(Error::Done) => {}
                Err(e) => {
                    return Err(e);
                }
            };
            self.flags.insert(InitiatedClientHandshake);
        }

        // Process all lost frames and prepare for retransmitting
        self.process_all_lost_frames();

        // Select a path for sending a packet
        let pid = self.select_send_path()?;

        // Limit bytes sent by path MTU limit and server send limit before address validation
        let mut left = cmp::min(out.len(), self.max_datagram_size(pid));
        left = self.paths.cmp_anti_ampl_limit(pid, left);

        let mut done = 0;

        // Write QUIC packets to the buffer
        let mut has_initial = false;
        while left > 0 {
            let (pkt_type, is_pmtu_probe, written) =
                match self.send_packet(&mut out[done..], left, pid, done == 0, has_initial) {
                    Ok(v) => v,
                    Err(Error::BufferTooShort) | Err(Error::Done) => break,
                    Err(e) => return Err(e),
                };

            left = left.saturating_sub(written);
            done = done.saturating_add(written);

            match pkt_type {
                PacketType::Initial => has_initial = true,

                // A packet with a short header does not include a length, so it
                // can only be the last packet included in a UDP datagram.
                PacketType::OneRTT => break,

                _ => (),
            }

            // The PMTU probe is not coalesced with other packets, since packets
            // that are larger than the current maximum datagram size are more
            // likely to be dropped by the network.
            if is_pmtu_probe {
                break;
            }
        }

        if done == 0 {
            return Err(Error::Done);
        }

        // Sending UDP datagrams carrying Initial packets of this size ensures
        // that the network path supports a reasonable Path Maximum Transmission
        // Unit (PMTU), in both directions. Initial packets can even be coalesced
        // with invalid packets, which a receiver will discard.
        // See RFC 9000 Section 14.1
        if has_initial && left > 0 && done < crate::MIN_CLIENT_INITIAL_LEN {
            let pad_len = cmp::min(left, crate::MIN_CLIENT_INITIAL_LEN - done);
            out[done..done + pad_len].fill(0);
            done += pad_len;
        }

        let path = self.paths.get(pid)?;
        let info = PacketInfo {
            src: path.local_addr(),
            dst: path.remote_addr(),
            time: time::Instant::now(),
        };
        Ok((done, info))
    }

    /// Write a QUIC packet to the given buffer.
    ///
    /// The `out` is the write buffer with a size that must be no less than `left`.
    /// The `left` is the upper limit for the write size when sending a non-PMTU
    /// probe packet.
    /// The `path_id` is the selected path for sending out packets.
    /// The `first` indicates that it is the first packet being written to the UDP
    /// datagram.
    /// The `has_initial` indicates that a previous Initial packet has been written
    /// the UDP datagram.
    ///
    /// Return a tuple consisting of the packet type, PMUT probe flag, and the
    /// packet size upon success.
    /// Return `Error::BufferTooShort` if the input buffer is too small to
    /// write a single QUIC packet.
    /// Return `Error::Done` if no packet can be sent.
    /// Return other Error if found unexpected error.
    fn send_packet(
        &mut self,
        out: &mut [u8],
        mut left: usize,
        path_id: usize,
        first: bool,
        has_initial: bool,
    ) -> Result<(PacketType, bool, usize)> {
        let now = time::Instant::now();

        if out.len() < left {
            return Err(Error::InvalidState("buffer too short".into()));
        }

        if self.is_draining() {
            return Err(Error::Done);
        }

        // Select packet type and encryption level
        let pkt_type = self.select_send_packet_type(path_id)?;
        let level = pkt_type.to_level()?;

        // Prepare and encode packet header (except for the Length and Packet Number field)
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let (pkt_num, pkt_num_len) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            let largest_acked = space.get_largest_acked_pkt();
            let pkt_num = space.next_pkt_num;
            let pkt_num_len = packet::packet_num_len(pkt_num, largest_acked);
            (pkt_num, pkt_num_len)
        };

        let dcid_seq = self
            .paths
            .get(path_id)?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let dcid = self.cids.get_dcid(dcid_seq)?.cid;

        let scid = if let Some(scid_seq) = self.paths.get(path_id)?.scid_seq {
            self.cids.get_scid(scid_seq)?.cid
        } else if pkt_type == PacketType::OneRTT {
            ConnectionId::default()
        } else {
            return Err(Error::InternalError);
        };

        let hdr = PacketHeader {
            pkt_type,
            version: self.version,
            dcid,
            scid,
            pkt_num: 0,
            pkt_num_len,
            token: if !self.is_server && pkt_type == PacketType::Initial {
                // Note: Retry packet is not sent by send_packet()
                self.token.clone()
            } else {
                None
            },
            key_phase: self.tls_session.current_key_phase(),
        };
        let hdr_offset = hdr.to_bytes(&mut out[..left])?;

        // Check the size of remaining space of the buffer
        let mut pkt_num_offset = hdr_offset;
        if pkt_type != PacketType::OneRTT {
            pkt_num_offset += crate::LENGTH_FIELD_LEN; // Reserved for Packet length field
        }
        let crypto_overhead = self
            .tls_session
            .get_overhead(level)
            .ok_or(Error::InternalError)?;
        let total_overhead = if !self.is_encryption_disabled(hdr.pkt_type) {
            pkt_num_offset + pkt_num_len + crypto_overhead
        } else {
            pkt_num_offset + pkt_num_len
        };

        match left.checked_sub(total_overhead) {
            Some(val) => left = val,
            None => {
                return Err(Error::BufferTooShort);
            }
        }
        if left < crate::MIN_PAYLOAD_LEN {
            return Err(Error::BufferTooShort);
        }

        // Encode packet number
        let len = packet::encode_packet_num(
            pkt_num,
            pkt_num_len,
            &mut out[pkt_num_offset..pkt_num_offset + pkt_num_len],
        )?;
        let payload_offset = pkt_num_offset + len;

        // Write frames into the packet payload
        let (ack_elicit_required, is_probe) = {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            (space.need_elicit_ack(), space.loss_probes > 0)
        };
        let mut write_status = FrameWriteStatus {
            ack_elicit_required,
            is_probe,
            overhead: total_overhead,
            ..FrameWriteStatus::default()
        };

        match self.send_frames(
            &mut out[payload_offset..],
            left,
            &mut write_status,
            pkt_type,
            path_id,
            first,
            has_initial,
        ) {
            Ok(..) => (),
            Err(Error::Done) if write_status.written > 0 => (), // at least one frame was written
            Err(e) => return Err(e),
        };

        // Fill in Length field of the packet header. This is the length of the
        // remainder of the packet (that is, the Packet Number and Payload
        // fields) in bytes
        let payload_len = write_status.written;
        if pkt_type != PacketType::OneRTT {
            // Note: This type of packet is always encrypted, even if the disable_1rtt_encryption
            // transport parameter is successfully negotiated.
            let len = pkt_num_len + payload_len + crypto_overhead;
            let mut out = &mut out[hdr_offset..];
            out.write_varint_with_len(len as u64, crate::LENGTH_FIELD_LEN)?;
        }

        // Encrypt the packet header fields and payload
        let key = self.tls_session.get_keys(pkt_type.to_level()?);
        let key = match &key.seal {
            Some(seal) => seal,
            None => return Err(Error::InternalError),
        };
        let mut cid_seq = None;
        if self.flags.contains(EnableMultipath) {
            cid_seq = Some(dcid_seq as u32);
        }

        let written = if !self.is_encryption_disabled(hdr.pkt_type) {
            packet::encrypt_packet(
                out,
                cid_seq,
                pkt_num,
                pkt_num_len,
                payload_len,
                payload_offset,
                None,
                key,
            )?
        } else {
            payload_offset + payload_len
        };

        let sent_pkt = space::SentPacket {
            pkt_type,
            pkt_num,
            time_sent: now,
            time_acked: None,
            time_lost: None,
            sent_size: written,
            ack_eliciting: write_status.ack_eliciting,
            in_flight: write_status.in_flight,
            has_data: write_status.has_data,
            pmtu_probe: write_status.is_pmtu_probe,
            pacing: write_status.pacing,
            frames: write_status.frames,
            rate_sample_state: Default::default(),
            buffer_flags: write_status.buffer_flags,
        };
        debug!(
            "{} sent packet {:?} {:?} {:?}",
            self.trace_id,
            hdr,
            &sent_pkt,
            self.paths.get(path_id)?
        );

        // Write events to qlog.
        #[cfg(feature = "qlog")]
        if let Some(qlog) = &mut self.qlog {
            // Write TransportPacketSent event to qlog.
            let mut qframes = Vec::with_capacity(sent_pkt.frames.len());
            for frame in &sent_pkt.frames {
                qframes.push(frame.to_qlog());
            }
            Self::qlog_quic_packet_sent(qlog, &hdr, pkt_num, written, payload_len, qframes);

            // Write RecoveryMetricsUpdate event to qlog.
            if let Ok(path) = self.paths.get_mut(path_id) {
                path.recovery.qlog_recovery_metrics_updated(qlog);
            }
        }

        // Notify the packet sent event to the multipath scheduler
        if let Some(ref mut scheduler) = self.multipath_scheduler {
            scheduler.on_sent(
                &sent_pkt,
                now,
                path_id,
                &mut self.paths,
                &mut self.spaces,
                &mut self.streams,
            );
        }

        // Clear app-limited state when sending in-flight data
        if write_status.in_flight {
            self.paths
                .get_mut(path_id)?
                .recovery
                .congestion
                .set_app_limited(false);
        }

        let handshake_status = self.handshake_status(self.paths.get(path_id)?);
        self.paths.get_mut(path_id)?.recovery.on_packet_sent(
            sent_pkt,
            space_id,
            &mut self.spaces,
            handshake_status,
            now,
        );

        if let Some(data) = write_status.challenge {
            // Record packet size and loss time if a PATH_CHALLENGE is sent.
            self.paths.on_path_chal_sent(path_id, data, written, now)?;
        }

        if write_status.is_pmtu_probe {
            self.paths
                .get_mut(path_id)?
                .dplpmtud
                .on_pmtu_probe_sent(written);
        }

        // Update connection state and statistic metrics
        self.stats.sent_count += 1;
        self.stats.sent_bytes += written as u64;
        self.paths
            .get_mut(path_id)?
            .recovery
            .stat_sent_event(1, written as u64);
        self.paths.dec_anti_ampl_limit(path_id, written);
        {
            let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
            space.next_pkt_num += 1;
            if pkt_type == PacketType::OneRTT {
                let lowest_1rtt_pkt_num = space.lowest_1rtt_pkt_num;
                space.lowest_1rtt_pkt_num = cmp::min(lowest_1rtt_pkt_num, pkt_num);
                if space.first_pkt_num_sent.is_none() {
                    space.first_pkt_num_sent = Some(pkt_num);
                }
            }
        }

        // The successful use of Handshake packets indicates that no more
        // Initial packets need to be exchanged, as these keys can only be
        // produced after receiving all CRYPTO frames from Initial packets.
        // Thus, a client MUST discard Initial keys when it first sends a
        // Handshake packet
        if !self.is_server && pkt_type == PacketType::Handshake {
            self.drop_space_state(SpaceId::Initial, now);
        }

        // An endpoint also restarts its idle timer when sending an ack-eliciting
        // packet if no other ack-eliciting packets have been sent since last
        // receiving and processing a packet.
        if write_status.ack_eliciting && !self.flags.contains(SentAckElicitingSinceRecvPkt) {
            if let Some(idle_timeout) = self.idle_timeout() {
                self.timers.set(Timer::Idle, now + idle_timeout);
            }
        }
        if write_status.ack_eliciting {
            self.flags.insert(SentAckElicitingSinceRecvPkt);
        }

        Ok((pkt_type, write_status.is_pmtu_probe, written))
    }

    /// Write QUIC frames to the payload of a QUIC packet.
    ///
    /// The current write offset in the `out` buffer is recorded in `st.written`
    /// Return Error::Done if there is no frame to send or no left room to write more frames.
    /// Return other Error if found unexpected error.
    #[allow(clippy::too_many_arguments)]
    fn send_frames(
        &mut self,
        buf: &mut [u8],
        left: usize,
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
        has_initial: bool,
    ) -> Result<()> {
        // Write an ACK frame
        self.try_write_ack_frame(&mut buf[..left], st, pkt_type, path_id)?;

        // Write a CONNECTION_CLOSE frame
        self.try_write_close_frame(&mut buf[..left], st, pkt_type, path_id)?;

        let path = self.paths.get_mut(path_id)?;
        path.recovery.stat_cwnd_limited();

        let now = time::Instant::now();
        let r = &mut self.paths.get_mut(path_id)?.recovery;

        // Check the congestion window
        // - Packets containing frames besides ACK or CONNECTION_CLOSE frames
        // count toward congestion control limits. (RFC 9002 Section 3)
        // - Probe packets are allowed to temporarily exceed the congestion
        // window. (RFC 9002 Section 4.7)
        if !st.is_probe && !r.can_send() {
            return Err(Error::Done);
        }
        st.pacing = true;

        // Write PMTU probe frames
        // Note: To probe the path MTU, the write size will exceed `left` but
        // not surpass the length of `buf`.
        self.try_write_pmut_probe_frames(buf, st, pkt_type, path_id, first)?;

        // Since it's not a PMTU probe packet, let's cap the buffer size for
        // simplicity.
        let out = &mut buf[..left];

        // Write PATH_CHALLENGE/PATH_RESPONSE frames
        self.try_write_path_validation_frames(out, st, pkt_type, path_id)?;

        // Write NEW_CONNECTION_ID/RETRIE_CONNECTION_ID frames
        self.try_write_cid_control_frame(out, st, pkt_type, path_id)?;

        // Write a HANDSHAKE_DONE frame
        if pkt_type == PacketType::OneRTT
            && !self.is_closing()
            && self.paths.get(path_id)?.active()
            && self.need_send_handshake_done_frame()
        {
            let frame = Frame::HandshakeDone;
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.flags.remove(NeedSendHandshakeDone);
        }

        // Write stream control frames
        self.try_write_stream_control_frames(out, st, pkt_type, path_id)?;

        // Write a CRYPTO frame
        self.try_write_crypto_frame(out, st, pkt_type, path_id)?;

        // Write buffered frames
        self.try_write_buffered_frames(out, st, pkt_type, path_id)?;

        // Write STREAM frames
        self.try_write_stream_frames(out, st, pkt_type, path_id)?;

        // Write a NEW_TOKEN frame
        self.try_write_new_token_frame(out, st, pkt_type, path_id)?;

        // Write DATAGRAM frames (RFC 9221)
        self.try_write_datagram_frames(out, st, pkt_type)?;

        // Write a PING frame
        if ((st.ack_elicit_required && !st.ack_eliciting)
            || self.paths.get_mut(path_id)?.need_send_ping)
            && !self.is_closing()
        {
            let frame = Frame::Ping { pmtu_probe: None };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.paths.get_mut(path_id)?.need_send_ping = false;
        }

        // No frames to be sent
        if st.frames.is_empty() {
            self.paths
                .get_mut(path_id)?
                .recovery
                .congestion
                .set_app_limited(true);
            return Err(Error::Done);
        }

        // Write PADDING frames
        if (out.len() - st.written >= 1)
            && (
                // Expand the payload of all UDP datagrams carrying Initial packets to
                // at least the smallest allowed maximum datagram size. Sending UDP
                // datagrams of this size ensures that the network path supports a
                // reasonable Path Maximum Transmission Unit (PMTU), in both directions.
                has_initial
                // To prevent deadlock when the server reaches its anti-amplification
                // limit, clients MUST send a packet on a Probe Timeout (PTO).
                // Specifically, the client MUST send an Initial packet in a UDP datagram
                // that contains at least 1200 bytes if it does not have Handshake keys,
                // and otherwise send a Handshake packet.
                || (st.is_probe && !self.is_server && pkt_type == PacketType::Handshake)
                // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE or
                // PATH_RESPONSE frame to at least the smallest allowed maximum datagram
                // size. This verifies that the path is able to carry datagrams of this
                // size in both directions.
                || self.paths.get(path_id)?.need_expand_padding_frames(self.is_server)
            )
        {
            let frame = Frame::Paddings {
                len: out.len() - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }
        if st.written < crate::MIN_PAYLOAD_LEN {
            let frame = Frame::Paddings {
                len: crate::MIN_PAYLOAD_LEN - st.written,
            };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.in_flight = true
        }

        Ok(())
    }

    /// Write PATH_RESPONSE/PATH_CHALLENGE frames if needed.
    fn try_write_path_validation_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT {
            return Ok(());
        }

        // Create PATH_RESPONSE frame if needed.
        while let Some(challenge) = self.paths.get_mut(path_id)?.pop_recv_chal() {
            let frame = Frame::PathResponse { data: challenge };

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
        }

        // Create PATH_CHALLENGE frame if needed.
        if self.paths.get(path_id)?.path_chal_initiated() {
            let data = rand::random::<u64>().to_be_bytes();
            let frame = Frame::PathChallenge { data };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            st.challenge = Some(data);
        }

        Ok(())
    }

    /// Write PMTU probe frames if needed.
    fn try_write_pmut_probe_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
        first: bool,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT
            || !self.flags.contains(HandshakeCompleted)
            || self.is_closing()
            || !first
            || !st.frames.is_empty()
        {
            return Ok(());
        }

        let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
        let path = self.paths.get_mut(path_id)?;
        let probe_size = path.dplpmtud.get_probe_size(peer_mds);
        if !path.validated()
            || !path.dplpmtud.should_probe()
            || probe_size > buf.len()
            || (probe_size as u64) > path.recovery.congestion.congestion_window()
            || path.recovery.congestion.in_recovery(time::Instant::now())
        {
            return Ok(());
        }

        // The content of the PMTU probe is limited to PING and PADDING frames.
        let frame = frame::Frame::Ping {
            pmtu_probe: Some((path_id, probe_size)),
        };
        Connection::write_frame_to_packet(frame, buf, st)?;

        let padding_len = probe_size - st.overhead - 1;
        let frame = frame::Frame::Paddings { len: padding_len };
        Connection::write_frame_to_packet(frame, buf, st)?;

        st.ack_eliciting = true;
        st.in_flight = true;
        st.is_pmtu_probe = true;

        // Finish writing the datagram to prevent it from coalescing with other
        // QUIC packets.
        Err(Error::Done)
    }

    /// Populate Acknowledgement frame to packet payload buffer.
    fn try_write_ack_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let is_closing = self.is_closing();
        let space_id = self.get_space_id(pkt_type, path_id)?;
        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;

        if space.recv_pkt_num_need_ack.is_empty()
            || !space.need_send_ack
            || is_closing
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        // Create ACK frame if needed.
        let ack_delay_exp = self.local_transport_params.ack_delay_exponent as u32;
        let ack_delay = space.largest_rx_pkt_time.elapsed();
        let ack_delay = ack_delay.as_micros() as u64 / 2_u64.pow(ack_delay_exp);
        let frame = Frame::Ack {
            ack_delay,
            ack_ranges: space.recv_pkt_num_need_ack.clone(),
            ecn_counts: None, // ECN not supported
        };
        Connection::write_frame_to_packet(frame, out, st)?;
        space.need_send_ack = false;
        space.ack_eliciting_pkts_since_last_sent_ack = 0;

        Ok(())
    }

    /// Populate Connection ID control frames to packet payload buffer.
    fn try_write_cid_control_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        // Create NEW_CONNECTION_ID frames as needed.
        while let Some(seq) = self.cids.next_scid_to_advertise() {
            let frame = self.cids.create_new_connection_id_frame(seq)?;

            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_scid_to_advertise(seq, false);
        }

        if !self.paths.get(path_id)?.active() {
            return Ok(());
        }

        // Create RETIRE_CONNECTION_ID frames as needed.
        while let Some(seq) = self.cids.next_dcid_to_retire() {
            // The sequence number specified in a RETIRE_CONNECTION_ID frame
            // MUST NOT refer to the Destination Connection ID field of the
            // packet in which the frame is contained.
            let dcid_seq = self
                .paths
                .get(path_id)?
                .dcid_seq
                .ok_or(Error::InternalError)?;
            if seq == dcid_seq {
                continue;
            }

            let frame = Frame::RetireConnectionId { seq_num: seq };
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
            self.cids.mark_dcid_to_retire(seq, false);

            if let Ok(cid) = self.cids.get_dcid(seq) {
                if let Some(token) = cid.reset_token {
                    let token = ResetToken(token.to_be_bytes());
                    self.events.add(Event::DcidRetired(token));
                }
            }
        }

        Ok(())
    }

    /// Populate Stream control frames to packet payload buffer.
    fn try_write_stream_control_frames(
        &mut self,
        buf: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // STREAM control frames can only be sent in 1-RTT packet.
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if !path.active() {
            return Ok(());
        }

        let now = time::Instant::now();

        // Create MAX_STREAMS frame if needed.
        for bidi in &[true, false] {
            if self.streams.should_update_local_max_streams(*bidi) {
                let frame = frame::Frame::MaxStreams {
                    bidi: *bidi,
                    max: self.streams.max_streams_next(*bidi),
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Apply the new max_streams limit.
                self.streams.update_local_max_streams(*bidi);
            }
        }

        // Create DATA_BLOCKED frame if needed.
        if let Some(blocked_at) = self.streams.data_blocked_at() {
            let frame = frame::Frame::DataBlocked { max: blocked_at };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            // Clear the data_blocked state.
            self.streams.update_data_blocked_at(None);
        }

        // Create MAX_STREAM_DATA frames if needed.
        for stream_id in self.streams.almost_full() {
            let stream = match self.streams.get_mut(stream_id) {
                Some(v) => v,

                None => {
                    // The stream closed, remove it from the almost full set.
                    self.streams.mark_almost_full(stream_id, false);
                    continue;
                }
            };

            // Adjust the stream window size automatically.
            stream
                .recv
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxStreamData {
                stream_id,
                max: stream.recv.max_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            let recv_win = stream.recv.window();
            // Apply the new flow control limit.
            stream.recv.update_max_data(now);
            self.streams.mark_almost_full(stream_id, false);

            // Ensure that the connection window always has some room
            // compared to the stream window.
            self.streams.ensure_window_lower_bound(
                (recv_win as f64 * crate::CONNECTION_WINDOW_FACTOR) as u64,
            );

            // When MAX_STREAM_DATA is sent, trigger MAX_DATA as well to avoid a
            // potential race condition.
            self.streams.rx_almost_full = true
        }

        // Create MAX_DATA frame if needed.
        if self.streams.need_send_max_data() {
            // Adjust the connection window size automatically.
            self.streams
                .autotune_window(now, path.recovery.rtt.smoothed_rtt());

            let frame = frame::Frame::MaxData {
                max: self.streams.max_rx_data_next(),
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.rx_almost_full = false;
            // Apply the new flow control limit.
            self.streams.update_max_rx_data(now);
        }

        // Create STOP_SENDING frames if needed.
        for (stream_id, error_code) in self
            .streams
            .stopped()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StopSending {
                stream_id,
                error_code,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_stopped(stream_id, false, 0);
        }

        // Create RESET_STREAM frames if needed.
        for (stream_id, (error_code, final_size)) in self
            .streams
            .reset()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, (u64, u64))>>()
        {
            let frame = frame::Frame::ResetStream {
                stream_id,
                error_code,
                final_size,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_reset(stream_id, false, 0, 0);
        }

        // Create STREAM_DATA_BLOCKED frames if needed.
        for (stream_id, limit) in self
            .streams
            .blocked()
            .map(|(&k, &v)| (k, v))
            .collect::<Vec<(u64, u64)>>()
        {
            let frame = frame::Frame::StreamDataBlocked {
                stream_id,
                max: limit,
            };

            Connection::write_frame_to_packet(frame, buf, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;

            self.streams.mark_blocked(stream_id, false, 0);
        }

        // Create STREAMS_BLOCKED frames if needed.
        for bidi in &[true, false] {
            if let Some(streams_blocked_at) = self.streams.streams_blocked_at(*bidi) {
                let frame = frame::Frame::StreamsBlocked {
                    bidi: *bidi,
                    max: streams_blocked_at,
                };

                Connection::write_frame_to_packet(frame, buf, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                // Clear the streams_blocked state.
                self.streams.update_streams_blocked_at(*bidi, None);
            }
        }

        Ok(())
    }

    /// Populate ConnectionClose frame to packet payload buffer.
    fn try_write_close_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // CONNECTION_CLOSE should be sent on the active path or the last available path.
        if !self.paths.get(path_id)?.active() && self.paths.len() > 1 {
            return Ok(());
        }

        if let Some(ref e) = self.local_error {
            let frame = if !e.is_app {
                Some(Frame::ConnectionClose {
                    error_code: e.error_code,
                    frame_type: 0,
                    reason: e.reason.clone(),
                })
            } else if pkt_type == PacketType::OneRTT || pkt_type == PacketType::ZeroRTT {
                // The application-specific variant of CONNECTION_CLOSE can
                // only be sent using 0-RTT or 1-RTT packets.
                // RFC 9000 Section 19.19
                Some(Frame::ApplicationClose {
                    error_code: e.error_code,
                    reason: e.reason.clone(),
                })
            } else {
                None
            };

            if let Some(frame) = frame {
                Connection::write_frame_to_packet(frame, out, st)?;
                st.ack_eliciting = true;
                st.in_flight = true;

                let pto = self.paths.get(path_id)?.recovery.rtt.pto_base();
                let draining_timeout = time::Instant::now() + pto * 3;
                self.timers.set(Timer::Draining, draining_timeout);
            }
        }

        Ok(())
    }

    /// Populate Crypto frame to packet payload buffer.
    fn try_write_crypto_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        // The CRYPTO frame is used to transmit cryptographic handshake messages
        // and can be sent in all packet types except 0-RTT.
        if pkt_type == PacketType::ZeroRTT {
            return Ok(());
        }

        let level = pkt_type.to_level()?;
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        let stream = crypto_streams.get_mut(level)?;
        let out = &mut out[st.written..];

        if !(stream.is_sendable()
            && out.len() > frame::MAX_CRYPTO_OVERHEAD
            && !self.is_closing()
            && self.paths.get(path_id)?.active())
        {
            return Ok(());
        }

        let crypto_off = stream.send.send_off();
        let frame_hdr_len = frame::crypto_header_wire_len(crypto_off);
        if out.len() <= frame_hdr_len {
            return Ok(());
        }

        let (frame_data_len, _) = stream.send.read(&mut out[frame_hdr_len..])?;
        frame::encode_crypto_header(crypto_off, frame_data_len as u64, out)?;
        st.written += frame_hdr_len + frame_data_len;
        st.frames.push(Frame::Crypto {
            offset: crypto_off,
            length: frame_data_len,
            data: Bytes::default(),
        });
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;

        Ok(())
    }

    /// Populate Stream frame to packet payload buffer.
    fn try_write_stream_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        let out = &mut out[st.written..];
        if (pkt_type != PacketType::OneRTT && pkt_type != PacketType::ZeroRTT)
            || self.is_closing()
            || out.len() <= frame::MAX_STREAM_OVERHEAD
            || !self.paths.get(path_id)?.active()
        {
            return Ok(());
        }

        let mut len = 0;
        let mut cap: usize = out.len();

        while let Some(stream_id) = self.streams.peek_sendable() {
            let stream = match self.streams.get_mut(stream_id) {
                // We should not send frames for streams that were already stopped.
                Some(s) if !s.send.is_stopped() => s,
                _ => {
                    self.streams.remove_sendable();
                    continue;
                }
            };

            // Get the lowest offset of data to be sent.
            let stream_off = stream.send.send_off();

            // Encode stream frame, instead of create a `frame::Frame::Stream`,
            // encode the data into the packet buffer directly.
            //
            // 1. Reserve some space in the output buffer for writing
            // the frame header.
            // 2. Read the data from the stream's SendBuf.
            // 3. encode the frame header with the updated frame header segments.
            let frame_hdr_len = frame::stream_header_wire_len(stream_id, stream_off);

            // Read stream data and write into the packet buffer directly.
            let (frame_data_len, fin) = stream.send.read(&mut out[len + frame_hdr_len..])?;

            // Retain stream data if needed.
            let data = if self.flags.contains(EnableMultipath)
                && buffer_required(self.multipath_conf.multipath_algorithm)
            {
                let start = len + frame_hdr_len;
                Bytes::copy_from_slice(&out[start..start + frame_data_len])
            } else {
                Bytes::new()
            };

            frame::encode_stream_header(
                stream_id,
                stream_off,
                frame_data_len as u64,
                fin,
                &mut out[len..len + frame_hdr_len],
            )?;

            let frame_len = frame_hdr_len + frame_data_len;
            st.written += frame_len;
            len += frame_len;
            cap -= frame_len;

            st.ack_eliciting = true;
            st.in_flight = true;
            st.has_data = true;
            st.frames.push(Frame::Stream {
                stream_id,
                offset: stream_off,
                length: frame_data_len,
                fin,
                data,
            });

            // If the stream is no longer sendable, remove it from the queue
            if !stream.is_sendable() {
                self.streams.remove_sendable();
            }

            // If the buffer is too short, we won't attempt to write any more stream frames into it.
            if cap <= frame::MAX_STREAM_OVERHEAD {
                break;
            }
        }

        Ok(())
    }

    /// Populate NewToken frame to packet payload buffer.
    fn try_write_new_token_frame(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !(pkt_type == PacketType::OneRTT
            && self.is_server
            && self.token.is_some()
            && !self.is_closing()
            && self.paths.get(path_id)?.active()
            && self.flags.contains(NeedSendNewToken))
        {
            return Ok(());
        }

        let frame = Frame::NewToken {
            token: self.token.clone().unwrap(), // always success
        };

        Connection::write_frame_to_packet(frame, out, st)?;
        st.ack_eliciting = true;
        st.in_flight = true;
        self.flags.remove(NeedSendNewToken);

        Ok(())
    }

    /// Write queued DATAGRAM frames into the packet payload buffer.
    ///
    /// Datagrams are sent best-effort. If the frame does not fit in the
    /// remaining packet space it is dropped (fire-and-forget semantics
    /// per RFC 9221).
    fn try_write_datagram_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
    ) -> Result<()> {
        if pkt_type != PacketType::OneRTT || self.is_closing() {
            return Ok(());
        }
        let peer_max = match self.peer_transport_params.max_datagram_frame_size {
            Some(v) if v > 0 => v as usize,
            _ => return Ok(()),
        };

        while let Some(data) = self.dgram_send_queue.pop_front() {
            let frame = Frame::Datagram { data };
            let wire = frame.wire_len();
            if wire > peer_max || wire > out.len() - st.written {
                // Frame too large or packet full – drop it.
                break;
            }
            Connection::write_frame_to_packet(frame, out, st)?;
            st.ack_eliciting = true;
            st.in_flight = true;
        }
        Ok(())
    }

    /// Populate buffered frame to packet payload buffer.
    fn try_write_buffered_frames(
        &mut self,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
        pkt_type: PacketType,
        path_id: usize,
    ) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Ok(());
        }

        let path = self.paths.get(path_id)?;
        if pkt_type != PacketType::OneRTT
            || self.is_closing()
            || out.len() - st.written <= frame::MAX_STREAM_OVERHEAD
            || !path.active()
        {
            return Ok(());
        }

        // Get buffered frames on the path.
        let space = self
            .spaces
            .get_mut(path.space_id)
            .ok_or(Error::InternalError)?;
        if space.buffered.is_empty() {
            return Ok(());
        }
        debug!(
            "{} try to write buffered frames: path_id={} frames={}",
            self.trace_id,
            path_id,
            space.buffered.len()
        );

        while let Some((frame, buffer_type)) = space.buffered.pop_front() {
            match frame {
                Frame::Stream {
                    stream_id,
                    offset,
                    length,
                    fin,
                    data,
                } => {
                    let stream = match self.streams.get_mut(stream_id) {
                        Some(v) => v,
                        _ => continue,
                    };

                    // Check acked range and write the first non-acked subrange
                    let range = offset..offset + length as u64;
                    if let Some(r) = stream.send.filter_acked(range) {
                        let data_len = Self::write_buffered_stream_frame_to_packet(
                            stream_id,
                            r.start,
                            fin && r.end == offset + length as u64,
                            data.slice((r.start - offset) as usize..(r.end - offset) as usize),
                            out,
                            buffer_type,
                            st,
                        )?;

                        // Processing the following subrange.
                        if r.start + (data_len as u64) < offset + length as u64 {
                            let tail_len =
                                (offset + length as u64 - r.start - data_len as u64) as usize;
                            let frame = Frame::Stream {
                                stream_id,
                                offset: r.start + data_len as u64,
                                length: tail_len,
                                fin,
                                data: data.slice(length - tail_len..),
                            };
                            space.buffered.push_front(frame, buffer_type);
                        }

                        if data_len == 0 {
                            break;
                        }
                    }
                }

                // Ignore other buffered frames.
                _ => continue,
            }
        }

        Ok(())
    }

    fn write_buffered_stream_frame_to_packet(
        stream_id: u64,
        offset: u64,
        mut fin: bool,
        mut data: Bytes,
        out: &mut [u8],
        buffer_type: BufferType,
        st: &mut FrameWriteStatus,
    ) -> Result<usize> {
        let out = &mut out[st.written..];
        if out.len() <= frame::MAX_STREAM_OVERHEAD {
            return Ok(0);
        }

        let hdr_len = frame::stream_header_wire_len(stream_id, offset);
        let data_len = cmp::min(data.len(), out.len() - hdr_len);
        if data_len < data.len() {
            data.truncate(data_len);
            fin = false;
        }

        frame::encode_stream_header(stream_id, offset, data_len as u64, fin, out)?;
        out[hdr_len..hdr_len + data.len()].copy_from_slice(&data);

        st.written += hdr_len + data_len;
        st.ack_eliciting = true;
        st.in_flight = true;
        st.has_data = true;
        st.buffer_flags.mark(buffer_type);
        st.frames.push(Frame::Stream {
            stream_id,
            offset,
            length: data.len(),
            fin,
            data,
        });
        Ok(data_len)
    }

    /// Populate a QUIC frame to the give buffer.
    fn write_frame_to_packet(
        frame: Frame,
        out: &mut [u8],
        st: &mut FrameWriteStatus,
    ) -> Result<()> {
        // Check whether there is enough room to write the frame.
        if st.written + frame.wire_len() > out.len() {
            return Err(Error::Done);
        }

        st.written += frame.to_bytes(&mut out[st.written..])?;
        st.frames.push(frame);
        Ok(())
    }

    /// Check whether a HANDHSAKE_DONE frame should be sent.
    fn need_send_handshake_done_frame(&self) -> bool {
        self.is_server && self.is_established() && self.flags.contains(NeedSendHandshakeDone)
    }

    /// Check whether a NEW_TOKEN frame should be sent.
    fn need_send_new_token_frame(&self) -> bool {
        self.is_server && self.is_established() && self.flags.contains(NeedSendNewToken)
    }

    /// Process lost frames in all packet number spaces and prepare for retransmitting
    ///
    /// QUIC packets that are determined to be lost are not retransmitted whole.
    /// The same applies to the frames that are contained within lost packets.
    /// Instead, the information that might be carried in frames is sent again
    /// in new frames as needed.
    /// See RFC 9000 Section 13.3
    fn process_all_lost_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for lost_frame in space.lost.drain(..) {
                match lost_frame {
                    // ACK frames carry the most recent set of acknowledgments and
                    // the acknowledgment delay from the largest acknowledged packet
                    Frame::Ack { .. } => {
                        space.need_send_ack = true;
                    }

                    // The HANDSHAKE_DONE frame MUST be retransmitted until it
                    // is acknowledged.
                    Frame::HandshakeDone if !self.flags.contains(HandshakeDoneAcked) => {
                        self.flags.insert(NeedSendHandshakeDone);
                    }

                    // New connection IDs are sent in NEW_CONNECTION_ID frames
                    // and retransmitted if the packet containing them is lost.
                    Frame::NewConnectionId { seq_num, .. } => {
                        self.cids.mark_scid_to_advertise(seq_num, true);
                    }

                    // Retired connection IDs are sent in RETIRE_CONNECTION_ID
                    // frames and retransmitted if the packet containing them is
                    // lost.
                    Frame::RetireConnectionId { seq_num } => {
                        self.cids.mark_dcid_to_retire(seq_num, true);
                    }

                    // NEW_TOKEN frames are retransmitted if the packet
                    // containing them is lost.
                    Frame::NewToken { .. } => {
                        self.flags.insert(NeedSendNewToken);
                    }

                    // Data sent in CRYPTO frames is retransmitted according to
                    // the rules in [QUIC-RECOVERY], until all data has been
                    // acknowledged.
                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = self.crypto_streams.borrow_mut();
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.retransmit(offset, length);
                        }
                    }

                    // Application data sent in STREAM frames is retransmitted
                    // in new STREAM frames unless the endpoint has sent a
                    // RESET_STREAM for that stream.
                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        fin,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_lost(stream_id, offset, length, fin);
                    }

                    // Cancellation of stream transmission, as carried in a
                    // RESET_STREAM frame, is sent until acknowledged or until
                    // all stream data is acknowledged by the peer.
                    Frame::ResetStream {
                        stream_id,
                        error_code,
                        final_size,
                    } => {
                        self.streams
                            .on_reset_stream_frame_lost(stream_id, error_code, final_size);
                    }

                    // An updated value is sent when the packet containing the
                    // most recent MAX_STREAM_DATA frame for a stream is lost.
                    Frame::MaxStreamData { stream_id, .. } => {
                        self.streams.on_max_stream_data_frame_lost(stream_id);
                    }

                    // An updated value is sent in a MAX_DATA frame if the packet
                    // containing the most recently sent MAX_DATA frame is
                    // declared lost.
                    Frame::MaxData { .. } => {
                        self.streams.on_max_data_frame_lost();
                    }

                    // Request that a peer cease transmission of data on a stream,
                    // as carried in a STOP_SENDING frame, is sent until acknowledged
                    // or until receive-side of the stream is finished.
                    Frame::StopSending {
                        stream_id,
                        error_code,
                    } => {
                        self.streams
                            .on_stop_sending_frame_lost(stream_id, error_code);
                    }

                    // Request that a peer update its max_streams limit, is sent until
                    // acknowledged or receive MAX_STREAMS frame from peer.
                    Frame::StreamsBlocked { bidi, max } => {
                        self.streams.on_streams_blocked_frame_lost(bidi, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a stream scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::StreamDataBlocked { stream_id, max } => {
                        self.streams
                            .on_stream_data_blocked_frame_lost(stream_id, max);
                    }

                    // A new frame is sent if a packet containing the most recent
                    // frame for a connection scope is lost, but only while the
                    // endpoint is blocked on the corresponding limit.
                    Frame::DataBlocked { max } => {
                        self.streams.on_data_blocked_frame_lost(max);
                    }

                    // An updated value is sent when a packet containing the
                    // most recent MAX_STREAMS for a stream type frame is
                    // declared lost.
                    Frame::MaxStreams { bidi, max } => {
                        self.streams.on_max_streams_frame_lost(bidi, max);
                    }

                    // A PING frame contain no information, so lost PING frames
                    // do not require repair. However, if it indicates the loss
                    // of a PMTU probe, we will try to schedule a new probe.
                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_lost(probe_size, peer_mds);
                            debug!(
                                "{} lost MTU probe on path {:?} size={}",
                                self.trace_id, path, probe_size
                            );
                        }
                    }

                    // DATAGRAM frames are never retransmitted (RFC 9221).
                    Frame::Datagram { .. } => (),

                    _ => (),
                }
            }
        }
    }

    /// Select an available path for sending packet
    ///
    /// The selected path should have a packet that can be sent out, unless none
    /// of the paths are feasible.
    fn select_send_path(&mut self) -> Result<usize> {
        // Select an unvalidated path with path probing packets to send
        if self.is_established() {
            let mut probing = self
                .paths
                .iter_mut()
                .filter(|(_, p)| p.dcid_seq.is_some())
                .filter(|(_, p)| p.need_send_validation_frames(self.is_server))
                .map(|(pid, _)| pid);

            if let Some(pid) = probing.next() {
                return Ok(pid);
            }
        }

        // Multipath scheduling for Multipath QUIC
        if self.flags.contains(EnableMultipath) {
            // Select a validated path with sufficient congestion window by the
            // multipath scheduler.
            if self.need_send_path_unaware_frames() {
                let s = match self.multipath_scheduler {
                    Some(ref mut scheduler) => scheduler,
                    None => return Err(Error::InternalError),
                };
                if let Ok(pid) = s.on_select(&mut self.paths, &mut self.spaces, &mut self.streams) {
                    return Ok(pid);
                }
            }

            // Select a validated path with ACK/PTO/Buffered packets to send.
            for (pid, path) in self.paths.iter_mut() {
                if !path.active() {
                    continue;
                }
                match self.spaces.get(path.space_id) {
                    Some(space) => {
                        if !space.recv_pkt_num_need_ack.is_empty() && space.need_send_ack {
                            return Ok(pid);
                        }
                        if space.loss_probes > 0 {
                            return Ok(pid);
                        }
                        if space.need_send_buffered_frames() && path.recovery.can_send() {
                            return Ok(pid);
                        }
                        if path.need_send_ping {
                            return Ok(pid);
                        }
                        continue;
                    }
                    None => continue,
                }
            }
        }

        // Select the active path
        self.paths.get_active_path_id()
    }

    /// Select packet type for outgoing packets
    fn select_send_packet_type(&mut self, pid: usize) -> Result<PacketType> {
        // When sending a CONNECTION_CLOSE frame, the goal is to ensure that
        // the peer will process the frame. Generally, this means sending the
        // frame in a packet with the highest level of packet protection to
        // avoid the packet being discarded.
        // See RFC 9000 Section 10.2.3
        if self.local_error.as_ref().is_some_and(|e| !e.is_app) {
            let pkt_type = match self.tls_session.write_level() {
                Level::Initial => PacketType::Initial,
                Level::Handshake => PacketType::Handshake,
                Level::ZeroRTT => unreachable!(),
                Level::OneRTT => PacketType::OneRTT,
            };

            // However, prior to confirming the handshake, it is possible that
            // more advanced packet protection keys are not available to the peer.
            if !self.is_established() {
                match pkt_type {
                    PacketType::OneRTT => return Ok(PacketType::Handshake),

                    PacketType::Handshake
                        if self.tls_session.get_keys(Level::Initial).seal.is_some() =>
                    {
                        return Ok(PacketType::Initial)
                    }

                    _ => (),
                };
            }
            return Ok(pkt_type);
        }

        // Coalescing packets in order of increasing encryption levels
        // (Initial, 0-RTT, Handshake, 1-RTT) makes it more likely that the
        // receiver will be able to process all the packets in a single pass.
        let pkt_types = [
            PacketType::Initial,
            PacketType::Handshake,
            PacketType::OneRTT,
        ];
        for pkt_type in pkt_types.iter() {
            // Only send packets in a space when we have the send keys for it.
            let level = pkt_type.to_level()?;
            if self.tls_session.get_keys(level).seal.is_none() {
                continue;
            }

            // We are ready to send data for this packet number space.
            let mut crypto_streams = self.crypto_streams.borrow_mut();
            if crypto_streams.get_mut(level)?.is_sendable() {
                return Ok(*pkt_type);
            }

            // We are ready to send ack for this packet number space.
            let space_id = self.get_space_id(*pkt_type, pid)?;
            let space = self.spaces.get(space_id).ok_or(Error::InternalError)?;
            if space.need_send_ack {
                return Ok(*pkt_type);
            }

            // There are lost frames in this packet number space.
            if !space.lost.is_empty() {
                return Ok(*pkt_type);
            }

            // We need to send PTO probe packets.
            if space.loss_probes > 0 {
                return Ok(*pkt_type);
            }
        }

        // If there are sendable, reset, stopped, almost full, blocked streams,
        // or need to update concurrency limits, use the 0RTT/1RTT packet.
        let path = self.paths.get(pid)?;
        if (self.is_established()
            // Note: The server's use of 1-RTT keys before the handshake is
            // complete is limited to sending data. BoringSSL will provide 1-RTT
            // write secret until the handshake is complete.
            // See RFC 9001 Section 5.7
            || self.tls_session.get_keys(Level::OneRTT).seal.is_some()
            || self.tls_session.is_in_early_data())
            && (self.need_send_handshake_done_frame()
                || self.need_send_new_token_frame()
                || self.local_error.as_ref().is_some_and(|e| e.is_app)
                || path.need_send_validation_frames(self.is_server)
                || path.dplpmtud.should_probe()
                || path.need_send_ping
                || self.cids.need_send_cid_control_frames()
                || self.streams.need_send_stream_frames()
                || self.spaces.need_send_buffered_frames())
        {
            if !self.is_server && self.tls_session.is_in_early_data() {
                return Ok(PacketType::ZeroRTT);
            }
            return Ok(PacketType::OneRTT);
        }

        Err(Error::Done)
    }

    /// Check whether there are any unsent frames that can be sent on any path.
    fn need_send_path_unaware_frames(&self) -> bool {
        self.need_send_handshake_done_frame()
            || self.need_send_new_token_frame()
            || self.local_error.as_ref().is_some_and(|e| e.is_app)
            || self.cids.need_send_cid_control_frames()
            || self.streams.need_send_stream_frames()
    }

    /// Find space id for the specified packet type and path id.
    pub(super) fn get_space_id(&self, pkt_type: PacketType, path_id: usize) -> Result<SpaceId> {
        if !self.flags.contains(EnableMultipath) {
            return pkt_type.to_space();
        }

        if pkt_type != PacketType::OneRTT {
            return pkt_type.to_space();
        }

        match self.paths.get(path_id) {
            Ok(path) => Ok(path.space_id),
            Err(e) => Err(e),
        }
    }
}
