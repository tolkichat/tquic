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

//! Getter/accessor methods, path management, stream operations, and timeout
//! handling for QUIC connections.

use super::*;

impl Connection {
    /// Set peer context for the specific path
    pub fn set_path_peer_context<T: Any + Send + Sync>(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
        ctx: T,
    ) -> Result<()> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        path.set_peer_context(ctx);
        Ok(())
    }

    /// Get peer context for the specific path
    pub fn path_peer_context(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<Option<&mut dyn Any>> {
        let path_id = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InternalError)?;

        let path = self.paths.get_mut(path_id)?;
        Ok(path.peer_context())
    }

    /// Select the path that the incoming packet belongs to, or creates a new
    /// one if no existing path matches.
    pub(super) fn get_or_create_path(
        &mut self,
        recv_pid: Option<usize>,
        dcid: &ConnectionId,
        info: &PacketInfo,
        buf_len: usize,
    ) -> Result<usize> {
        // Note: If the incoming packet carrys an unknown dcid, just ignore and drop it.
        let (cid_seq, mut cid_pid) = self.cids.find_scid(dcid).ok_or(Error::Done)?;

        // The incoming packet arrived on the existing path (for Client/Server).
        if let Some(recv_pid) = recv_pid {
            let recv_path = self.paths.get_mut(recv_pid)?;
            let cid_item = recv_path.scid_seq.and_then(|v| self.cids.get_scid(v).ok());

            if cid_item.map(|c| &c.cid) != Some(dcid) {
                recv_path.scid_seq = Some(cid_seq);
                self.cids.mark_scid_used(cid_seq, recv_pid)?;
            }
            return Ok(recv_pid);
        }

        // The incoming packet arrived on a new path (for Server).
        if self.cids.zero_length_scid() {
            cid_pid = None;
        }
        let mut path = path::Path::new(
            info.dst,
            info.src,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );
        if self.is_server {
            path.anti_ampl_limit = buf_len * self.paths.anti_ampl_factor;
        }

        path.scid_seq = Some(cid_seq);
        path.initiate_path_chal();

        // Try to create a packet number space for the new path in MPQUIC mode.
        if self.flags.contains(EnableMultipath) {
            match cid_pid {
                None => {
                    // Found a new path initiated by client
                    let space_id = self.spaces.add();
                    path.space_id = space_id;
                }
                Some(cid_pid) => {
                    // Found NAT rebinding: If path migration occurs, the new path
                    // will simply share the same packet number space with the
                    // original path.
                    path.space_id = self.paths.get(cid_pid)?.space_id;
                }
            }
        }

        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);
        if cid_pid.is_none() {
            self.cids.mark_scid_used(cid_seq, pid)?;
        }
        Ok(pid)
    }

    /// Return the amount of time until the next timeout event.
    pub(crate) fn timeout(&mut self) -> Option<time::Duration> {
        if self.is_closed() {
            return None;
        }

        let time = if self.is_draining() {
            // Draining timer takes precedence over all other timers. If it is
            // set, it means the connection is in draining state and there's
            // need to process the other timers.
            self.timers.get(Timer::Draining)
        } else {
            // Use the lowest timer among all the other timers
            match self.paths.min_loss_detection_timer() {
                Some(time) => self.timers.set(Timer::LossDetection, time),
                None => self.timers.stop(Timer::LossDetection),
            }
            match self.paths.min_pacer_timer() {
                Some(time) => self.timers.set(Timer::Pacer, time),
                None => self.timers.stop(Timer::Pacer),
            }
            match self.paths.min_path_chal_timer() {
                Some(time) => self.timers.set(Timer::PathChallenge, time),
                None => self.timers.stop(Timer::PathChallenge),
            }
            match self.spaces.min_ack_timer() {
                Some(time) => self.timers.set(Timer::Ack, time),
                None => self.timers.stop(Timer::Ack),
            }

            self.timers.next_timeout()
        };

        // Calculate duration since now.
        let d = time.map(|v| {
            let now = time::Instant::now();
            if v <= now {
                time::Duration::ZERO
            } else {
                v.duration_since(now)
            }
        });
        trace!("{} next timeout duration {:?}", self.trace_id(), d);
        d
    }

    /// Process timeout event on the connection.
    pub(crate) fn on_timeout(&mut self, now: time::Instant) {
        for timer in Timer::iter() {
            if !self.timers.is_expired(timer, now) {
                continue;
            }
            trace!("{} timer {:?} timeout", self.trace_id, timer);

            self.timers.stop(timer);
            match timer {
                Timer::LossDetection => {
                    // Compute connection-level handshake status parts before the loop.
                    let keys = self.tls_session.get_keys(Level::Handshake);
                    let derived_handshake_keys = keys.seal.is_some() && keys.open.is_some();
                    let peer_verified_address = self.flags.contains(PeerVerifiedInitialAddress);
                    let completed = self.is_established();
                    let is_server = self.is_server;

                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.loss_detection_timer() {
                            if timer > now {
                                continue;
                            }
                            // Compute path-specific anti-amplification limit status.
                            let at_amplification_limit = is_server
                                && !path.verified_peer_address
                                && path.anti_ampl_limit == 0;
                            let handshake_status = HandshakeStatus {
                                derived_handshake_keys,
                                peer_verified_address,
                                completed,
                                is_server,
                                at_amplification_limit,
                            };
                            let (lost_pkts, lost_bytes) = path.recovery.on_loss_detection_timeout(
                                path.space_id,
                                &mut self.spaces,
                                handshake_status,
                                #[cfg(feature = "qlog")]
                                self.qlog.as_mut(),
                                now,
                            );
                            self.stats.lost_count += lost_pkts;
                            self.stats.lost_bytes += lost_bytes;

                            // Write RecoveryMetricsUpdate event to qlog.
                            #[cfg(feature = "qlog")]
                            if let Some(qlog) = &mut self.qlog {
                                path.recovery.qlog_recovery_metrics_updated(qlog);
                            }
                        }
                    }
                }

                Timer::Ack => {
                    for (_, space) in self.spaces.iter_mut() {
                        if let Some(timer) = space.ack_timer {
                            if timer > now {
                                continue;
                            }
                            debug!("{} ack timeout for space {:?}", self.trace_id, space.id);
                            space.need_send_ack = true;
                            space.ack_timer = None;
                        }
                    }
                }

                Timer::Pacer => {
                    for (_, path) in self.paths.iter_mut() {
                        if let Some(timer) = path.recovery.pacer_timer {
                            if timer > now {
                                continue;
                            }
                        }
                        path.recovery.pacer_timer = None;
                    }
                    self.mark_tickable(true);
                }

                Timer::Idle => {
                    info!("{} idle timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(IdleTimeout);
                }

                Timer::Draining => self.flags.insert(Closed),

                Timer::KeyDiscard => self.tls_session.discard_prev_key(),

                Timer::KeepAlive => {
                    let _ = self.paths.mark_ping(None);
                }

                Timer::PathChallenge => self.paths.on_path_chal_timeout(now),

                Timer::Handshake => {
                    info!("{} handshake timeout", self.trace_id);
                    self.flags.insert(Closed);
                    self.flags.insert(HandshakeTimeout);
                }
            }
        }
    }

    /// Return the idle timeout of the connection.
    pub(super) fn idle_timeout(&mut self) -> Option<time::Duration> {
        // The idle timeout is disabled.
        if self.local_transport_params.max_idle_timeout == 0
            && self.peer_transport_params.max_idle_timeout == 0
        {
            return None;
        }

        // The effective value at an endpoint is computed as the minimum of
        // the two advertised values.
        let idle_timeout = if self.local_transport_params.max_idle_timeout == 0 {
            self.peer_transport_params.max_idle_timeout
        } else if self.peer_transport_params.max_idle_timeout == 0 {
            self.local_transport_params.max_idle_timeout
        } else {
            cmp::min(
                self.local_transport_params.max_idle_timeout,
                self.peer_transport_params.max_idle_timeout,
            )
        };
        let idle_timeout = time::Duration::from_millis(idle_timeout);

        // To avoid excessively small idle timeout periods, endpoints MUST
        // increase the idle timeout period to be at least three times the
        // current Probe Timeout (PTO).
        // See RFC 9000 Section 10.1
        let path_pto = match self.paths.get_active_mut() {
            Ok(p) => p.recovery.rtt.pto_base(),
            Err(_) => time::Duration::ZERO,
        };
        let idle_timeout = cmp::max(idle_timeout, 3 * path_pto);

        Some(idle_timeout)
    }

    /// Whether encryption on the specified packet type should be disabled
    pub(super) fn is_encryption_disabled(&self, pkt_type: PacketType) -> bool {
        pkt_type == PacketType::OneRTT && self.flags.contains(DisableEncryption)
    }

    /// Check whether the connection is a server connection.
    pub fn is_server(&self) -> bool {
        self.is_server
    }

    /// Check whether the connection handshake is complete.
    pub fn is_established(&self) -> bool {
        self.flags.contains(HandshakeCompleted)
    }

    /// Check whether the connection handshake is confirmed.
    pub fn is_confirmed(&self) -> bool {
        self.flags.contains(HandshakeConfirmed)
    }

    /// Check whether the connection is resumed.
    pub fn is_resumed(&self) -> bool {
        self.tls_session.is_resumed()
    }

    /// Check whether the connection has a pending handshake that has progressed
    /// enough to send or receive early data.
    pub fn is_in_early_data(&self) -> bool {
        self.tls_session.is_in_early_data()
    }

    /// Check whether the multipath have been negotiated.
    pub fn is_multipath(&self) -> bool {
        self.flags.contains(EnableMultipath)
    }

    /// Return the negotiated application level protocol.
    pub fn application_proto(&self) -> &[u8] {
        self.tls_session.alpn_protocol()
    }

    /// Return the server name in the TLS SNI extension.
    pub fn server_name(&self) -> Option<&str> {
        self.tls_session.server_name()
    }

    /// Return the session data used by resumption.
    pub fn session(&self) -> Option<&[u8]> {
        self.tls_session.session()
    }

    /// Return details why 0-RTT was accepted or rejected.
    pub fn early_data_reason(&self) -> tls::SslEarlyDataReason {
        self.tls_session.early_data_reason()
    }

    /// Return a string representation for reason why 0-RTT was accepted or rejected.
    pub fn early_data_reason_string(&self) -> Result<Option<&str>> {
        self.tls_session.early_data_reason_string()
    }

    /// Check whether the connection is draining.
    ///
    /// If true, the connection object can not yet be dropped, but no data can
    /// be sent or received.
    pub fn is_draining(&self) -> bool {
        self.timers.get(Timer::Draining).is_some()
    }

    /// Check whether the connection is closing.
    pub fn is_closing(&self) -> bool {
        self.local_error.is_some()
    }

    /// Check whether the connection is closed.
    ///
    /// If true, the connection object can be dropped.
    pub fn is_closed(&self) -> bool {
        self.flags.contains(Closed)
    }

    /// Check whether the connection was closed due to idle timeout.
    pub fn is_idle_timeout(&self) -> bool {
        self.flags.contains(IdleTimeout)
    }

    /// Check whether the connection was closed due to handshake timeout.
    pub fn is_handshake_timeout(&self) -> bool {
        self.flags.contains(HandshakeTimeout)
    }

    /// Check whether the connection was closed due to stateless reset.
    pub fn is_reset(&self) -> bool {
        self.flags.contains(GotReset)
    }

    /// Close the connection.
    pub fn close(&mut self, app: bool, err: u64, reason: &[u8]) -> Result<()> {
        if self.is_closed() || self.is_draining() {
            return Err(Error::Done);
        }

        if self.local_error.is_some() {
            return Err(Error::Done);
        }

        self.local_error = Some(ConnectionError {
            is_app: app,
            error_code: err,
            frame: None,
            reason: reason.to_vec(),
        });
        self.mark_tickable(true);
        Ok(())
    }

    /// Mark the connection as stateless reset by the peer.
    pub(crate) fn reset(&mut self) {
        if self.is_closed() || self.is_draining() {
            return;
        }

        // The connection is reset by the peer and it MUST enter the draining
        // period and not send any further packets on this connection.
        self.flags.insert(GotReset);
        if let Ok(p) = self.paths.get_active_mut() {
            let pto = p.recovery.rtt.pto_base();
            let now = time::Instant::now();
            self.timers.set(Timer::Draining, now + pto * 3);
        }
    }

    /// Returns the error from the peer, if any.
    pub fn peer_error(&self) -> Option<&ConnectionError> {
        self.peer_error.as_ref()
    }

    /// Returns the local error, if any.
    pub fn local_error(&self) -> Option<&ConnectionError> {
        self.local_error.as_ref()
    }

    /// Return statistics about the connection.
    pub fn stats(&self) -> &ConnectionStats {
        &self.stats
    }

    /// Discard packet number space and related secrets.
    ///
    /// After QUIC has completed a move to a new encryption level, packet
    /// protection keys for previous encryption levels can be discarded.
    /// This occurs several times during the handshake, as well as when keys
    /// are updated.
    /// See RFC 9001 Section 4.9
    pub(super) fn drop_space_state(&mut self, sid: SpaceId, now: time::Instant) {
        let level = match sid {
            SpaceId::Initial => Level::Initial,
            SpaceId::Handshake => Level::Handshake,
            _ => return,
        };

        // Discard unused keys for given level
        if self.tls_session.get_keys(level).open.is_none() {
            return;
        }
        self.tls_session.drop_keys(level);
        let mut crypto_streams = self.crypto_streams.borrow_mut();
        crypto_streams.clear(level);

        // When Initial and Handshake packet protection keys are discarded, all
        // packets that were sent with those keys can no longer be acknowledged
        // because their acknowledgments cannot be processed.
        // The sender MUST discard all recovery state associated with those
        // packets and MUST remove them from the count of bytes in flight.
        if let Ok(path) = self.paths.get_active() {
            let handshake_status = self.handshake_status(path);
            if let Ok(path) = self.paths.get_active_mut() {
                path.recovery.on_pkt_num_space_discarded(
                    sid,
                    &mut self.spaces,
                    handshake_status,
                    now,
                );
            }
        }
    }

    /// Return the handshake status for loss recovery.
    ///
    /// The `path` parameter is used to determine if the server is at the
    /// anti-amplification limit for the given path.
    pub(super) fn handshake_status(&self, path: &path::Path) -> HandshakeStatus {
        let keys = self.tls_session.get_keys(Level::Handshake);

        // The server is at the anti-amplification limit when it cannot send
        // any more data until it receives more data from the client.
        // This happens when the peer address is not yet verified and the
        // amplification limit has been exhausted.
        let at_amplification_limit =
            self.is_server && !path.verified_peer_address && path.anti_ampl_limit == 0;

        HandshakeStatus {
            derived_handshake_keys: keys.seal.is_some() && keys.open.is_some(),
            peer_verified_address: self.flags.contains(PeerVerifiedInitialAddress),
            completed: self.is_established(),
            is_server: self.is_server,
            at_amplification_limit,
        }
    }

    /// Return scid of the active path
    pub fn scid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .scid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_scid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over source ConnectionIdItem
    pub fn scid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.scid_iter()
    }

    /// Provide additional source CID and trigger sending NEW_CONNECTION_ID
    /// frames.
    pub(crate) fn add_scid(
        &mut self,
        scid: ConnectionId,
        reset_token: u128,
        retire_if_needed: bool,
    ) -> Result<u64> {
        self.cids
            .add_scid(scid, Some(reset_token), true, None, retire_if_needed)
    }

    /// Return true if the source CID is zero length
    pub fn zero_length_scid(&self) -> bool {
        self.cids.zero_length_scid()
    }

    /// Return dcid of the active path
    pub fn dcid(&self) -> Result<ConnectionId> {
        let seq = self
            .paths
            .get_active()?
            .dcid_seq
            .ok_or(Error::InternalError)?;
        let item = self.cids.get_dcid(seq)?;
        Ok(item.cid)
    }

    /// Return an iterator over destination ConnectionIdItem
    pub fn dcid_iter(&self) -> impl Iterator<Item = &ConnectionIdItem> {
        self.cids.dcid_iter()
    }

    /// Return true if the destination CID is zero length
    pub fn zero_length_dcid(&self) -> bool {
        self.cids.zero_length_dcid()
    }

    /// Return original destination cid
    pub(crate) fn odcid(&self) -> Option<ConnectionId> {
        if self.is_server {
            self.local_transport_params
                .original_destination_connection_id
        } else {
            self.odcid
        }
    }

    /// Return the unique trace id.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    /// Set dcid provided by peer
    pub(super) fn try_set_dcid_for_initial_path(
        &mut self,
        pid: usize,
        hdr: &PacketHeader,
    ) -> Result<()> {
        if self.flags.contains(GotPeerCid) {
            return Ok(());
        }

        if !self.is_server {
            if self.odcid.is_none() {
                self.odcid = Some(self.dcid()?);
            }
            self.set_initial_dcid(
                hdr.scid,
                self.peer_transport_params.stateless_reset_token,
                pid,
            )?;
        } else {
            self.set_initial_dcid(
                hdr.scid,
                self.peer_transport_params.stateless_reset_token,
                pid,
            )?;

            if !self.flags.contains(DidRetry) {
                self.local_transport_params
                    .original_destination_connection_id = Some(hdr.dcid);
                self.set_transport_params()?;
            }
        }

        self.flags.insert(GotPeerCid);
        Ok(())
    }

    /// Set dcid for initial path of the connection
    pub(super) fn set_initial_dcid(
        &mut self,
        cid: ConnectionId,
        reset_token: Option<u128>,
        path_id: usize,
    ) -> Result<()> {
        self.cids.set_initial_dcid(cid, reset_token, Some(path_id));
        self.paths.get_mut(path_id)?.dcid_seq = Some(0);

        Ok(())
    }

    /// Configure tls session to send transport parameters in the
    /// quic_transport_parameters extension in either the ClientHello or
    /// EncryptedExtensions handshake message.
    pub(super) fn set_transport_params(&mut self) -> Result<()> {
        let mut raw_params = [0; 128];
        let len = TransportParams::encode(
            &self.local_transport_params,
            self.is_server,
            &mut raw_params,
        )?;
        self.tls_session.set_transport_params(&raw_params[..len])?;
        Ok(())
    }

    /// Return a func for writing crypto data from the TLS session to the crypto stream.
    pub(super) fn get_write_method(&mut self) -> tls::WriteMethod {
        let crypto_streams = self.crypto_streams.clone();
        Box::new(move |level, data| {
            let mut crypto_streams = crypto_streams.borrow_mut();
            let stream = crypto_streams.get_mut(level)?;
            stream.send.write(Bytes::copy_from_slice(data), false)?;
            Ok(())
        })
    }

    /// Send a Ping frame for keep-alive.
    ///
    /// If `path_addr` is `None`, a Ping frame will be sent on each active path.
    /// Otherwise, a Ping frame will be on the specified path.
    pub fn ping(&mut self, path_addr: Option<FourTuple>) -> Result<()> {
        self.paths.mark_ping(path_addr)
    }

    /// Client add a new path on the connection.
    pub fn add_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<u64> {
        if self.is_server {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        if !self.flags.contains(HandshakeCompleted) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        if self.paths.get_path_id(&(local_addr, remote_addr)).is_some() {
            return Err(Error::Done);
        }

        let dcid_seq = if self.cids.zero_length_dcid() {
            Some(0)
        } else {
            self.cids.lowest_unused_dcid_seq()
        };

        let mut path = path::Path::new(
            local_addr,
            remote_addr,
            false,
            &self.recovery_conf,
            &self.trace_id,
        );
        path.dcid_seq = dcid_seq;
        let pid = self.paths.insert_path(path)?;
        self.paths.get_mut(pid)?.update_trace_id(pid);

        if let Some(dcid_seq) = dcid_seq {
            self.cids.mark_dcid_used(dcid_seq, pid)?;
        }

        let path = self.paths.get_mut(pid)?;
        path.initiate_path_chal();

        // Create packet number space for the path when Multipath QUIC is enabled.
        if self.flags.contains(EnableMultipath) {
            let space_id = self.spaces.add();
            path.space_id = space_id;
        }

        self.mark_tickable(true);
        Ok(pid as u64)
    }

    /// Abandon a path for a Multipath QUIC connection.
    #[doc(hidden)]
    pub fn abandon_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        if !self.flags.contains(EnableMultipath) {
            return Err(Error::InvalidOperation("disallowed".into()));
        }

        let pid = match self.paths.get_path_id(&(local_addr, remote_addr)) {
            Some(pid) => pid,
            None => return Ok(()),
        };

        // Don't allow abandoning the last active path
        let path = self.paths.get(pid)?;
        if path.active() {
            let active_count = self.paths.iter().filter(|(_, p)| p.active()).count();
            if active_count <= 1 {
                return Err(Error::InvalidOperation(
                    "cannot abandon last active path".into(),
                ));
            }
        }

        // Mark the path as abandoned.
        let path = self.paths.get_mut(pid)?;
        path.is_abandon = true;
        Ok(())
    }

    /// Return an immutable reference to the specified path
    pub fn get_path(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&path::Path> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        self.paths.get(pid)
    }

    /// Return an immutable reference to the active path
    pub fn get_active_path(&self) -> Result<&path::Path> {
        self.paths.get_active()
    }

    /// Return an mutable reference to the specified path
    pub fn get_path_stats(
        &mut self,
        local_addr: SocketAddr,
        remote_addr: SocketAddr,
    ) -> Result<&crate::PathStats> {
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("not found".into()))?;
        Ok(self.paths.get_mut(pid)?.stats())
    }

    /// Migrates the connection to the specified path.
    ///
    /// This function switches the active path for the connection to the specified
    /// path identified by local and remote addresses. The target path must already
    /// exist (created via `add_path` or by receiving packets on a new path).
    ///
    /// In single-path mode, the old active path is marked as non-active.
    /// In multipath mode, multiple paths can remain active simultaneously.
    ///
    /// If the target path has not been validated yet, path validation will be
    /// initiated automatically.
    #[doc(hidden)]
    pub fn migrate_path(&mut self, local_addr: SocketAddr, remote_addr: SocketAddr) -> Result<()> {
        // Migration is only allowed after handshake is complete
        if !self.flags.contains(HandshakeCompleted) {
            return Err(Error::InvalidOperation("handshake not completed".into()));
        }

        // Find the target path
        let pid = self
            .paths
            .get_path_id(&(local_addr, remote_addr))
            .ok_or(Error::InvalidOperation("path not found".into()))?;

        // Check that the path is not in a failed state
        let path = self.paths.get(pid)?;
        if path.state() == path::PathState::Failed {
            return Err(Error::InvalidOperation("path validation failed".into()));
        }

        // Check if the path is already active
        if path.active() {
            return Ok(());
        }

        // Ensure the path has a dcid_seq allocated
        // If not, try to allocate one from available connection IDs
        let path = self.paths.get_mut(pid)?;
        if path.dcid_seq.is_none() {
            let dcid_seq = if self.cids.zero_length_dcid() {
                Some(0)
            } else {
                self.cids.lowest_unused_dcid_seq()
            };

            if let Some(seq) = dcid_seq {
                path.dcid_seq = Some(seq);
                self.cids.mark_dcid_used(seq, pid)?;
            } else {
                // No available connection ID for migration
                return Err(Error::InvalidOperation("no available connection ID".into()));
            }
        }

        // In non-multipath mode, mark the old active path as non-active
        if !self.flags.contains(EnableMultipath) {
            if let Ok(old_active_path) = self.paths.get_active_mut() {
                old_active_path.set_active(false);
            }
        }

        // Set the new path as active
        let path = self.paths.get_mut(pid)?;
        path.set_active(true);

        // If the path is not validated, initiate path validation
        if !path.validated() && !path.path_chal_initiated() {
            path.initiate_path_chal();
        }

        self.mark_tickable(true);
        Ok(())
    }

    /// Return an iterator over path addresses.
    pub fn paths_iter(&self) -> FourTupleIter {
        // Instead of trying to identify whether packets will be sent on the
        // given 4-tuple, simply filter paths that cannot be used.
        FourTupleIter {
            addrs: self
                .paths
                .iter()
                .map(|(_, p)| FourTuple {
                    local: p.local_addr(),
                    remote: p.remote_addr(),
                })
                .collect(),
        }
    }

    /// Return an iterator over streams that have data to read or an error to collect.
    pub fn stream_readable_iter(&self) -> StreamIter {
        self.streams.readable_iter()
    }

    /// Return an iterator over streams that can be written
    pub fn stream_writable_iter(&self) -> StreamIter {
        self.streams.writable_iter()
    }

    /// Return an iterator over all the existing streams on the connection.
    pub fn stream_iter(&self) -> StreamIter {
        self.streams.iter()
    }

    /// Return true if the stream has enough flow control capacity to send data
    /// and application wants to send more data.
    pub(crate) fn stream_check_writable(&self, stream_id: u64) -> bool {
        self.streams.check_writable(stream_id)
    }

    /// Return true if application wants to read more data from the stream.
    pub(crate) fn stream_check_readable(&self, stream_id: u64) -> bool {
        self.streams.check_readable(stream_id)
    }

    /// Set want write flag for a stream.
    pub fn stream_want_write(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_write(stream_id, want)
    }

    /// Set want read flag for a stream.
    pub fn stream_want_read(&mut self, stream_id: u64, want: bool) -> Result<()> {
        self.mark_tickable(true);
        self.streams.want_read(stream_id, want)
    }

    /// Read data from a stream
    pub fn stream_read(&mut self, stream_id: u64, out: &mut [u8]) -> Result<(usize, bool)> {
        self.mark_tickable(true);
        let read_off = self.streams.stream_read_offset(stream_id);

        match self.streams.stream_read(stream_id, out) {
            Ok((read, fin)) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_read(qlog, stream_id, read_off.unwrap_or(0), read);
                }

                Ok((read, fin))
            }
            Err(e) => Err(e),
        }
    }

    /// Write data to a stream.
    pub fn stream_write(&mut self, stream_id: u64, buf: Bytes, fin: bool) -> Result<usize> {
        self.mark_tickable(true);
        let write_off = self.streams.stream_write_offset(stream_id);

        match self.streams.stream_write(stream_id, buf, fin) {
            Ok(written) => {
                // Write QuicStreamDataMoved event to qlog
                #[cfg(feature = "qlog")]
                if let Some(qlog) = &mut self.qlog {
                    Self::qlog_transport_data_write(
                        qlog,
                        stream_id,
                        write_off.unwrap_or(0),
                        written,
                    );
                }
                Ok(written)
            }
            Err(e) => Err(e),
        }
    }

    /// Create a new stream with given stream id and priority.
    /// This is a low-level API for stream creation. It is recommended to use
    /// `stream_bidi_new` for bidirectional streams or `stream_uni_new` for
    /// undirectional streams.
    pub fn stream_new(&mut self, stream_id: u64, urgency: u8, incremental: bool) -> Result<()> {
        self.stream_set_priority(stream_id, urgency, incremental)
    }

    /// Create a new bidirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_bidi_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_bidi_new(urgency, incremental)
    }

    /// Create a new undirectional stream with given stream priority.
    /// Return id of the created stream upon success.
    pub fn stream_uni_new(&mut self, urgency: u8, incremental: bool) -> Result<u64> {
        self.mark_tickable(true);
        self.streams.stream_uni_new(urgency, incremental)
    }

    /// Shutdown stream reading or writing.
    pub fn stream_shutdown(&mut self, stream_id: u64, direction: Shutdown, err: u64) -> Result<()> {
        self.mark_tickable(true);
        self.streams.stream_shutdown(stream_id, direction, err)
    }

    /// Set priority for a stream.
    pub fn stream_set_priority(
        &mut self,
        stream_id: u64,
        urgency: u8,
        incremental: bool,
    ) -> Result<()> {
        self.mark_tickable(true);
        self.streams
            .stream_set_priority(stream_id, urgency, incremental)
    }

    /// Return the stream's send capacity in bytes.
    pub fn stream_capacity(&self, stream_id: u64) -> Result<usize> {
        self.streams.stream_capacity(stream_id)
    }

    /// Return true if the stream has enough send capacity.
    pub fn stream_writable(&mut self, stream_id: u64, len: usize) -> Result<bool> {
        self.streams.stream_writable(stream_id, len)
    }

    /// Return true if the stream has data to be read or an error to be collected.
    pub fn stream_readable(&self, stream_id: u64) -> bool {
        self.streams.stream_readable(stream_id)
    }

    /// Return true if the stream's receive-side final size is known,
    /// and the application has read all data from the stream.
    pub fn stream_finished(&self, stream_id: u64) -> bool {
        self.streams.stream_finished(stream_id)
    }

    /// Set user context for a stream.
    pub fn stream_set_context<T: Any + Send + Sync>(
        &mut self,
        stream_id: u64,
        ctx: T,
    ) -> Result<()> {
        self.streams.stream_set_context(stream_id, ctx)
    }

    /// Return the stream's user context.
    pub fn stream_context(&mut self, stream_id: u64) -> Option<&mut dyn Any> {
        self.streams.stream_context(stream_id)
    }

    /// Return immutable reference to streams
    pub(crate) fn get_streams(&self) -> &stream::StreamMap {
        &self.streams
    }

    /// Destroy the closed stream. It's only used by the Endpoint.
    pub(crate) fn stream_destroy(&mut self, stream_id: u64) {
        self.streams.stream_destroy(stream_id);
    }

    /// Return the internal identifier of the connection on the Endpoint. The
    /// internal identifier is not the same as the Connection ID as described
    /// in RFC 9000.
    pub fn index(&self) -> Option<u64> {
        self.index
    }

    /// Set the connection index on the Endpoint. It also enable generating
    /// endpoint-facing events.
    pub(crate) fn set_index(&mut self, v: u64) {
        self.index = Some(v);
        self.events.enable();
        self.streams.events.enable();
    }

    /// Set the queues shared by the endpoint and the connection.
    pub(crate) fn set_queues(&mut self, queues: Rc<RefCell<ConnectionQueues>>) {
        self.queues = Some(queues);
    }

    /// Client start handshake.
    pub(crate) fn start_handshake(&mut self) -> Result<()> {
        if self.is_server {
            return Ok(());
        }

        match self.tls_session.process() {
            Ok(_) => Ok(()),
            Err(Error::Done) => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Return an endpoint-facing event.
    pub(crate) fn poll(&mut self) -> Option<Event> {
        if let Some(event) = self.events.poll() {
            return Some(event);
        }
        if let Some(event) = self.streams.events.poll() {
            return Some(event);
        }
        None
    }

    /// Check whether internal events should be processed.
    pub(crate) fn is_ready(&mut self) -> bool {
        !self.events.is_empty()
            || !self.streams.events.is_empty()
            || self.streams.has_readable()
            || self.streams.has_writable()
            || self.is_closed()
    }

    /// Check whether the connection is tickable (i.e. on the tickable queue
    /// of the endpoint)
    pub(crate) fn is_tickable(&self) -> bool {
        self.flags.contains(Tickable)
    }

    /// Mark the connection as tickable.
    pub(crate) fn mark_tickable(&mut self, tickable: bool) {
        if tickable == self.is_tickable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if tickable {
                queues.tickable.insert(idx);
                self.flags.insert(Tickable);
            } else {
                queues.tickable.remove(&idx);
                self.flags.remove(Tickable);
            }
            trace!("{} marked tickable {}", self.trace_id, tickable);
        }
    }

    /// Check whether the connection is sendable (i.e. on the sendable queue
    /// of the endpoint)
    pub(crate) fn is_sendable(&self) -> bool {
        self.flags.contains(Sendable)
    }

    /// Mark the connection as sendable.
    pub(crate) fn mark_sendable(&mut self, sendable: bool) {
        if sendable == self.is_sendable() {
            return;
        }

        if let Some(idx) = self.index {
            let mut queues = match &self.queues {
                Some(v) => v.borrow_mut(),
                None => unreachable!(),
            };
            if sendable {
                queues.sendable.insert(idx);
                self.flags.insert(Sendable);
            } else {
                queues.sendable.remove(&idx);
                self.flags.remove(Sendable);
            }
            trace!("{} marked sendable {}", self.trace_id, sendable);
        }
    }

    /// Get user context for the connection.
    pub fn context(&mut self) -> Option<&mut dyn Any> {
        match self.context {
            Some(ref mut data) => Some(data.as_mut()),
            None => None,
        }
    }

    /// Set user context for the connection.
    pub fn set_context<T: Any + Send + Sync>(&mut self, data: T) {
        self.context = Some(Box::new(data))
    }

    /// Write a QuicParametersSet event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_quic_params_set(
        qlog: &mut qlog::QlogWriter,
        params: &TransportParams,
        owner: events::Owner,
        cipher: Option<tls::Algorithm>,
    ) {
        let ev_data = params.to_qlog(owner, cipher);
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketReceived event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_quic_packet_received(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let ev_data = events::EventData::QuicPacketReceived {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            trigger: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicPacketSent event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_quic_packet_sent(
        qlog: &mut qlog::QlogWriter,
        hdr: &PacketHeader,
        pkt_num: u64,
        pkt_len: usize,
        payload_len: usize,
        qlog_frames: Vec<qlog::events::QuicFrame>,
    ) {
        let qlog_pkt_hdr = events::PacketHeader::new_with_type(
            hdr.pkt_type.to_qlog(),
            pkt_num,
            Some(hdr.version),
            Some(&hdr.scid),
            Some(&hdr.dcid),
        );
        let qlog_raw_info = events::RawInfo {
            length: Some(pkt_len as u64),
            payload_length: Some(payload_len as u64),
            data: None,
        };
        let now = time::Instant::now();

        let ev_data = events::EventData::QuicPacketSent {
            header: qlog_pkt_hdr,
            frames: Some(qlog_frames.into()),
            is_coalesced: None,
            retry_token: None,
            stateless_reset_token: None,
            supported_versions: None,
            raw: Some(qlog_raw_info),
            datagram_id: None,
            is_mtu_probe_packet: None,
            trigger: None,
        };
        qlog.add_event_data(now, ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_quic_data_acked(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        offset: u64,
        length: usize,
    ) {
        let ev_data = events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(offset),
            length: Some(length as u64),
            from: Some(events::DataRecipient::Transport),
            to: Some(events::DataRecipient::Dropped),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_transport_data_read(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        read_off: u64,
        read: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(read_off),
            length: Some(read as u64),
            from: Some(qlog::events::DataRecipient::Transport),
            to: Some(qlog::events::DataRecipient::Application),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }

    /// Write a QuicStreamDataMoved event to the qlog.
    #[cfg(feature = "qlog")]
    pub(super) fn qlog_transport_data_write(
        qlog: &mut qlog::QlogWriter,
        stream_id: u64,
        write_off: u64,
        written: usize,
    ) {
        let ev_data = qlog::events::EventData::QuicStreamDataMoved {
            stream_id: Some(stream_id),
            offset: Some(write_off),
            length: Some(written as u64),
            from: Some(qlog::events::DataRecipient::Application),
            to: Some(qlog::events::DataRecipient::Transport),
            raw: None,
        };
        qlog.add_event_data(time::Instant::now(), ev_data).ok();
    }
}
