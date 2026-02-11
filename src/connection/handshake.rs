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

//! Handshake and control frame scheduling for QUIC connections.

use super::*;

use crate::shared_borrow_mut;

impl Connection {
    /// Prepare for sending NEW_CONNECTION_ID/NEW_TOKEN frames.
    pub(super) fn try_schedule_control_frames(&mut self) {
        // An endpoint SHOULD ensure that its peer has a sufficient number of
        // available and unused connection IDs. An endpoint MUST NOT provide
        // more connection IDs than the peer's limit.
        let id_limit = cmp::min(
            self.peer_transport_params.active_conn_id_limit,
            crate::MAX_CID_LIMIT,
        );
        let num = (id_limit - 1) as u8;
        self.events.add(Event::ScidToAdvertise(num));

        // A server sends a NEW_TOKEN frame to provide the client with a token
        // to send in the header of an Initial packet for a future connection.
        if self.is_server && self.token.is_some() {
            self.flags.insert(NeedSendNewToken);
        }
    }

    /// Try to buffer undecryptable packets when the keys are not yet available.
    pub(super) fn try_buffer_undecryptable_packets(
        &mut self,
        hdr: &PacketHeader,
        pkt: Vec<u8>,
        info: &PacketInfo,
    ) {
        if self.is_established()
            || (self.is_server
                && hdr.pkt_type != PacketType::ZeroRTT
                && hdr.pkt_type != PacketType::OneRTT)
            || (!self.is_server
                && hdr.pkt_type != PacketType::Handshake
                && hdr.pkt_type != PacketType::OneRTT)
        {
            trace!("{} drop packet {:?}", self.trace_id, hdr);
            return;
        }

        if self.undecryptable_packets.push(&hdr.pkt_type, pkt, info) {
            trace!("{} buffer undecryptable packets: {:?}", self.trace_id, hdr);
        } else {
            trace!(
                "{} key not yet available, drop packet {:?}",
                self.trace_id,
                hdr
            );
        }
    }

    /// Try to process undecryptable packets.
    pub(super) fn try_process_undecryptable_packets(&mut self) {
        if self.undecryptable_packets.all_empty() {
            return;
        }

        let pkt_types = if self.is_server {
            vec![PacketType::ZeroRTT, PacketType::OneRTT]
        } else {
            vec![PacketType::Handshake, PacketType::OneRTT]
        };

        for pkt_type in pkt_types {
            if self.undecryptable_packets.is_empty(&pkt_type) {
                continue;
            }

            let level = pkt_type.to_level().unwrap();
            let key = self.tls_session.get_keys(level);
            if key.open.is_none() {
                continue;
            }

            while let Some((mut pkt, info)) = self.undecryptable_packets.pop(&pkt_type) {
                if let Err(e) = self.recv(&mut pkt, &info) {
                    error!(
                        "{} try process undecryptable packet error {:?} type {:?}",
                        self.trace_id, e, pkt_type
                    );
                }
            }
        }
    }

    /// Check and schedule an ACK frame to acknowledge incoming packets.
    pub(super) fn try_schedule_ack_frame(
        &mut self,
        space_id: SpaceId,
        pkt_num: u64,
        ack_eliciting: bool,
    ) -> Result<()> {
        if !ack_eliciting {
            return Ok(());
        }

        let space = self.spaces.get_mut(space_id).ok_or(Error::InternalError)?;
        if space.need_send_ack {
            return Ok(());
        }

        // An endpoint MUST acknowledge all ack-eliciting Initial and Handshake
        // packets immediately
        if space.id == SpaceId::Initial || space.id == SpaceId::Handshake {
            space.need_send_ack = true;
            return Ok(());
        }

        // A receiver SHOULD send an ACK frame after receiving at least two
        // ack-eliciting packets.
        space.ack_eliciting_pkts_since_last_sent_ack += 1;
        let ack_eliciting_threshold = self.recovery_conf.ack_eliciting_threshold;
        if space.ack_eliciting_pkts_since_last_sent_ack >= ack_eliciting_threshold {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // In order to assist loss detection at the sender, an endpoint SHOULD
        // generate and send an ACK frame without delay when it receives an
        // ack-eliciting packet either:
        // - when the received packet has a packet number less than another
        //   ack-eliciting packet that has been received, or
        // - when the packet has a packet number larger than the highest-numbered
        // ack-eliciting packet that has been received and there are missing
        // packets between that packet and this packet.
        if pkt_num < space.largest_rx_ack_eliciting_pkt_num
            || pkt_num > space.largest_rx_ack_eliciting_pkt_num + 1
        {
            space.need_send_ack = true;
            space.ack_timer = None;
            return Ok(());
        }

        // All ack-eliciting 0-RTT and 1-RTT packets within its advertised
        // max_ack_delay.
        if space.ack_timer.is_none() {
            let ack_delay = time::Duration::from_millis(self.peer_transport_params.max_ack_delay);
            space.ack_timer = Some(time::Instant::now() + ack_delay);
            debug!(
                "{} set ack timer for space {:?}, timeout {:?} ",
                &self.trace_id, space_id, space.ack_timer
            );
        }
        Ok(())
    }

    /// Process acknowledged frames in each packet number space
    pub(super) fn try_process_acked_frames(&mut self) {
        for (_, space) in self.spaces.iter_mut() {
            for acked_frame in space.acked.drain(..) {
                match acked_frame {
                    // When a packet containing an ACK frame is acknowledged by
                    // the peer, the endpoint can stop acknowledging packets
                    // less than or equal to the Largest Acknowledged field in
                    // the sent ACK frame.
                    Frame::Ack { ack_ranges, .. } => {
                        if let Some(largest_acked) = ack_ranges.max() {
                            space.recv_pkt_num_need_ack.remove_until(largest_acked);
                        }
                    }

                    Frame::Crypto { offset, length, .. } => {
                        let level = space.id.to_level();
                        let mut crypto_streams = shared_borrow_mut(&self.crypto_streams);
                        if let Ok(stream) = crypto_streams.get_mut(level) {
                            stream.send.ack_and_drop(offset, length);
                        }
                    }

                    // HandshakeDone has been successfully deliveried to client.
                    Frame::HandshakeDone => {
                        self.flags.remove(NeedSendHandshakeDone);
                        self.flags.insert(HandshakeDoneAcked);
                    }

                    Frame::Stream {
                        stream_id,
                        offset,
                        length,
                        ..
                    } => {
                        self.streams
                            .on_stream_frame_acked(stream_id, offset, length);

                        // Write QuicStreamDataMoved event to qlog
                        #[cfg(feature = "qlog")]
                        if let Some(qlog) = &mut self.qlog {
                            Self::qlog_quic_data_acked(qlog, stream_id, offset, length);
                        }
                    }

                    Frame::ResetStream { stream_id, .. } => {
                        self.streams.on_reset_stream_frame_acked(stream_id);
                    }

                    Frame::Ping {
                        pmtu_probe: Some((path_id, probe_size)),
                    } => {
                        if let Ok(path) = self.paths.get_mut(path_id) {
                            let peer_mds = self.peer_transport_params.max_udp_payload_size as usize;
                            path.dplpmtud.on_pmtu_probe_acked(probe_size, peer_mds);
                            let current = path.dplpmtud.get_current_size();
                            path.recovery.update_max_datagram_size(current, false);
                            debug!("{} path {:?} MTU is {} now", self.trace_id, path, current);
                        }
                    }

                    // Datagrams are fire-and-forget; no action on ACK.
                    Frame::Datagram { .. } => (),

                    _ => (),
                }
            }
        }
    }

    /// If any path doesn't has a DCID, try to allocate one for it.
    pub(super) fn try_allocate_cids_from_peer(&mut self) {
        let paths_no_dcid = self.paths.iter_mut().filter(|(_, p)| p.dcid_seq.is_none());

        for (pid, path) in paths_no_dcid {
            if self.cids.zero_length_dcid() {
                path.dcid_seq = Some(0);
                continue;
            }

            let dcid_seq = match self.cids.lowest_unused_dcid_seq() {
                Some(seq) => seq,
                None => break,
            };
            let _ = self.cids.mark_dcid_used(dcid_seq, pid); // alaways success
            path.dcid_seq = Some(dcid_seq);
        }
    }
}
