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

use std::ptr;
use std::slice;
use std::sync::Arc;

use libc::c_int;
use libc::c_void;
use libc::size_t;

use crate::error::Error;
use crate::tls::TlsConfig;
use crate::CongestionControlAlgorithm;
use crate::Config;
use crate::MultipathAlgorithm;
use crate::MultipathBondMode;

use super::tls_config::TlsConfigSelectMethods;
use super::tls_config::TlsConfigSelector;
use super::tls_config::TlsConfigSelectorContext;

/// Create default configuration.
/// The caller is responsible for the memory of the Config and should properly
/// destroy it by calling `quic_config_free`.
#[no_mangle]
pub extern "C" fn quic_config_new() -> *mut Config {
    match Config::new() {
        Ok(conf) => Box::into_raw(Box::new(conf)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a Config instance.
#[no_mangle]
pub extern "C" fn quic_config_free(config: *mut Config) {
    unsafe {
        let _ = Box::from_raw(config);
    };
}

/// Set the `max_idle_timeout` transport parameter in milliseconds.
#[no_mangle]
pub extern "C" fn quic_config_set_max_idle_timeout(config: &mut Config, v: u64) {
    config.set_max_idle_timeout(v);
}

/// Set handshake timeout in milliseconds. Zero turns the timeout off.
#[no_mangle]
pub extern "C" fn quic_config_set_max_handshake_timeout(config: &mut Config, v: u64) {
    config.set_max_handshake_timeout(v);
}

/// Set the `max_udp_payload_size` transport parameter in bytes. It limits
/// the size of UDP payloads that the endpoint is willing to receive.
#[no_mangle]
pub extern "C" fn quic_config_set_recv_udp_payload_size(config: &mut Config, v: u16) {
    config.set_recv_udp_payload_size(v);
}

/// Enable the Datagram Packetization Layer Path MTU Discovery
/// default value is true.
#[no_mangle]
pub extern "C" fn enable_dplpmtud(config: &mut Config, v: bool) {
    config.enable_dplpmtud(v);
}

/// Set the maximum outgoing UDP payload size in bytes.
/// It corresponds to the maximum datagram size that DPLPMTUD tries to discovery.
/// The default value is `1200` which means let DPLPMTUD choose a value.
#[no_mangle]
pub extern "C" fn quic_config_set_send_udp_payload_size(config: &mut Config, v: usize) {
    config.set_send_udp_payload_size(v);
}

/// Set the `initial_max_data` transport parameter. It means the initial
/// value for the maximum amount of data that can be sent on the connection.
/// The value is capped by the setting `max_connection_window`.
/// The default value is `10485760`.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_data(config: &mut Config, v: u64) {
    config.set_initial_max_data(v);
}

/// Set the `initial_max_stream_data_bidi_local` transport parameter.
/// The value is capped by the setting `max_stream_window`.
/// The default value is `5242880`.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_bidi_local(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_local(v);
}

/// Set the `initial_max_stream_data_bidi_remote` transport parameter.
/// The value is capped by the setting `max_stream_window`.
/// The default value is `2097152`.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_bidi_remote(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_bidi_remote(v);
}

/// Set the `initial_max_stream_data_uni` transport parameter.
/// The value is capped by the setting `max_stream_window`.
/// The default value is `1048576`.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_stream_data_uni(config: &mut Config, v: u64) {
    config.set_initial_max_stream_data_uni(v);
}

/// Set the `initial_max_streams_bidi` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_streams_bidi(config: &mut Config, v: u64) {
    config.set_initial_max_streams_bidi(v);
}

/// Set the `initial_max_streams_uni` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_max_streams_uni(config: &mut Config, v: u64) {
    config.set_initial_max_streams_uni(v);
}

/// Set the `ack_delay_exponent` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_ack_delay_exponent(config: &mut Config, v: u64) {
    config.set_ack_delay_exponent(v);
}

/// Set the `max_ack_delay` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_max_ack_delay(config: &mut Config, v: u64) {
    config.set_max_ack_delay(v);
}

/// Set congestion control algorithm that the connection would use.
#[no_mangle]
pub extern "C" fn quic_config_set_congestion_control_algorithm(
    config: &mut Config,
    v: CongestionControlAlgorithm,
) {
    config.set_congestion_control_algorithm(v);
}

/// Set the initial congestion window in packets.
/// The default value is 10.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_congestion_window(config: &mut Config, v: u64) {
    config.set_initial_congestion_window(v);
}

/// Set the minimal congestion window in packets.
/// The default value is 2.
#[no_mangle]
pub extern "C" fn quic_config_set_min_congestion_window(config: &mut Config, v: u64) {
    config.set_min_congestion_window(v);
}

/// Set the threshold for slow start in packets.
/// The default value is the maximum value of u64.
#[no_mangle]
pub extern "C" fn quic_config_set_slow_start_thresh(config: &mut Config, v: u64) {
    config.set_slow_start_thresh(v);
}

/// Set the minimum duration for BBR ProbeRTT state in milliseconds.
/// The default value is 200 milliseconds.
#[no_mangle]
pub extern "C" fn quic_config_set_bbr_probe_rtt_duration(config: &mut Config, v: u64) {
    config.set_bbr_probe_rtt_duration(v);
}

/// Enable using a cwnd based on bdp during ProbeRTT state.
/// The default value is false.
#[no_mangle]
pub extern "C" fn quic_config_enable_bbr_probe_rtt_based_on_bdp(config: &mut Config, v: bool) {
    config.enable_bbr_probe_rtt_based_on_bdp(v);
}

/// Set the cwnd gain for BBR ProbeRTT state.
/// The default value is 0.75
#[no_mangle]
pub extern "C" fn quic_config_set_bbr_probe_rtt_cwnd_gain(config: &mut Config, v: f64) {
    config.set_bbr_probe_rtt_cwnd_gain(v);
}

/// Set the length of the BBR RTProp min filter window in milliseconds.
/// The default value is 10000 milliseconds.
#[no_mangle]
pub extern "C" fn quic_config_set_bbr_rtprop_filter_len(config: &mut Config, v: u64) {
    config.set_bbr_rtprop_filter_len(v);
}

/// Set the cwnd gain for BBR ProbeBW state.
/// The default value is 2.0
#[no_mangle]
pub extern "C" fn quic_config_set_bbr_probe_bw_cwnd_gain(config: &mut Config, v: f64) {
    config.set_bbr_probe_bw_cwnd_gain(v);
}

/// Set the delta in copa slow start state.
#[no_mangle]
pub extern "C" fn quic_config_set_copa_slow_start_delta(config: &mut Config, v: f64) {
    config.set_copa_slow_start_delta(v);
}

/// Set the delta in coap steady state.
#[no_mangle]
pub extern "C" fn quic_config_set_copa_steady_delta(config: &mut Config, v: f64) {
    config.set_copa_steady_delta(v);
}

/// Enable Using the rtt standing instead of the latest rtt to calculate queueing delay.
#[no_mangle]
pub extern "C" fn quic_config_enable_copa_use_standing_rtt(config: &mut Config, v: bool) {
    config.enable_copa_use_standing_rtt(v);
}

/// Set the initial RTT in milliseconds. The default value is 333ms.
/// The configuration should be changed with caution. Setting a value less than the default
/// will cause retransmission of handshake packets to be more aggressive.
#[no_mangle]
pub extern "C" fn quic_config_set_initial_rtt(config: &mut Config, v: u64) {
    config.set_initial_rtt(v);
}

/// Enable pacing to smooth the flow of packets sent onto the network.
/// The default value is true.
#[no_mangle]
pub extern "C" fn quic_config_enable_pacing(config: &mut Config, v: bool) {
    config.enable_pacing(v);
}

/// Set clock granularity used by the pacer.
/// The default value is 10 milliseconds.
#[no_mangle]
pub extern "C" fn quic_config_set_pacing_granularity(config: &mut Config, v: u64) {
    config.set_pacing_granularity(v);
}

/// Set the linear factor for calculating the probe timeout.
/// The endpoint do not backoff the first `v` consecutive probe timeouts.
/// The default value is `0`.
/// The configuration should be changed with caution. Setting a value greater than the default
/// will cause retransmission to be more aggressive.
#[no_mangle]
pub extern "C" fn quic_config_set_pto_linear_factor(config: &mut Config, v: u64) {
    config.set_pto_linear_factor(v);
}

/// Set the upper limit of probe timeout in milliseconds.
/// A Probe Timeout (PTO) triggers the sending of one or two probe datagrams and enables a
/// connection to recover from loss of tail packets or acknowledgments.
/// See RFC 9002 Section 6.2.
#[no_mangle]
pub extern "C" fn quic_config_set_max_pto(config: &mut Config, v: u64) {
    config.set_max_pto(v);
}

/// Set the `active_connection_id_limit` transport parameter.
#[no_mangle]
pub extern "C" fn quic_config_set_active_connection_id_limit(config: &mut Config, v: u64) {
    config.set_active_connection_id_limit(v);
}

/// Set the `enable_multipath` transport parameter.
/// The default value is false. (Experimental)
#[no_mangle]
pub extern "C" fn quic_config_enable_multipath(config: &mut Config, enabled: bool) {
    config.enable_multipath(enabled);
}

/// Set the multipath scheduling algorithm
/// The default value is MultipathAlgorithm::MinRtt
#[no_mangle]
pub extern "C" fn quic_config_set_multipath_algorithm(config: &mut Config, v: MultipathAlgorithm) {
    config.set_multipath_algorithm(v);
}

/// Set the multipath bonding mode.
/// The default value is MultipathBondMode::Aggregate
#[no_mangle]
pub extern "C" fn quic_config_set_multipath_bond_mode(config: &mut Config, v: MultipathBondMode) {
    config.set_multipath_bond_mode(v);
}

/// Set the BLEST scheduler lambda parameter.
/// Higher values make the scheduler more aggressive in avoiding slow paths.
/// The default value is 0.5
#[no_mangle]
pub extern "C" fn quic_config_set_blest_lambda(config: &mut Config, v: f64) {
    config.set_blest_lambda(v);
}

/// Set the RTT threshold for failover mode in microseconds.
/// When a path's RTT exceeds this, traffic may failover to backup.
/// The default value is 0 (disabled).
#[no_mangle]
pub extern "C" fn quic_config_set_failover_rtt_threshold(config: &mut Config, us: u64) {
    config.set_failover_rtt_threshold(us);
}

/// Set the path timeout in milliseconds.
/// Paths are marked as failed after this timeout without response.
/// The default value is 30000 (30 seconds).
#[no_mangle]
pub extern "C" fn quic_config_set_path_timeout(config: &mut Config, ms: u64) {
    config.set_path_timeout(ms);
}

/// Set the path probe interval in milliseconds.
/// The default value is 1000 (1 second).
#[no_mangle]
pub extern "C" fn quic_config_set_path_probe_interval(config: &mut Config, ms: u64) {
    config.set_path_probe_interval(ms);
}

/// Set the maximum size of the connection flow control window.
/// The default value is MAX_CONNECTION_WINDOW (15 MB).
#[no_mangle]
pub extern "C" fn quic_config_set_max_connection_window(config: &mut Config, v: u64) {
    config.set_max_connection_window(v);
}

/// Set the maximum size of the stream flow control window.
/// The value should not be greater than the setting `max_connection_window`.
/// The default value is MAX_STREAM_WINDOW (6 MB).
#[no_mangle]
pub extern "C" fn quic_config_set_max_stream_window(config: &mut Config, v: u64) {
    config.set_max_stream_window(v);
}

/// Set the Maximum number of concurrent connections.
#[no_mangle]
pub extern "C" fn quic_config_set_max_concurrent_conns(config: &mut Config, v: u32) {
    config.set_max_concurrent_conns(v);
}

/// Set the key for reset token generation. The token_key_len should be not less
/// than 64.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_reset_token_key(
    config: &mut Config,
    token_key: *const u8,
    token_key_len: size_t,
) -> c_int {
    const RTK_LEN: usize = 64;
    if token_key_len < RTK_LEN {
        let e = Error::InvalidConfig("reset token key".into());
        return e.to_errno() as c_int;
    };

    let token_key = unsafe { slice::from_raw_parts(token_key, RTK_LEN) };
    let mut key = [0; RTK_LEN];
    key.copy_from_slice(token_key);
    config.set_reset_token_key(key);
    0
}

/// Set the lifetime of address token.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_address_token_lifetime(config: &mut Config, seconds: u64) {
    config.set_address_token_lifetime(seconds);
}

/// Set the key for address token generation. It also enables retry.
/// The token_key_len should be a multiple of 16.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_address_token_key(
    config: &mut Config,
    token_keys: *const u8,
    token_keys_len: size_t,
) -> c_int {
    const ATK_LEN: usize = 16;
    if token_keys_len < ATK_LEN || token_keys_len % ATK_LEN != 0 {
        let e = Error::InvalidConfig("address token key".into());
        return e.to_errno() as c_int;
    }

    let mut token_keys = unsafe { slice::from_raw_parts(token_keys, token_keys_len) };
    let mut keys = Vec::new();
    while !token_keys.is_empty() {
        let mut key = [0u8; ATK_LEN];
        key.copy_from_slice(&token_keys[..ATK_LEN]);
        keys.push(key);
        token_keys = &token_keys[ATK_LEN..];
    }

    match config.set_address_token_key(keys) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set whether stateless retry is allowed. Default is not allowed.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_enable_retry(config: &mut Config, enabled: bool) {
    config.enable_retry(enabled);
}

/// Set whether stateless reset is allowed.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_enable_stateless_reset(config: &mut Config, enabled: bool) {
    config.enable_stateless_reset(enabled);
}

/// Set the length of source cid. The length should not be greater than 20.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_set_cid_len(config: &mut Config, v: u8) {
    config.set_cid_len(v as usize);
}

/// Set the anti-amplification factor.
///
/// The server limits the data sent to an unvalidated address to
/// `anti_amplification_factor` times the received data.
#[no_mangle]
pub extern "C" fn quic_config_set_anti_amplification_factor(config: &mut Config, v: u8) {
    config.set_anti_amplification_factor(v as usize);
}

/// Set the batch size for sending packets.
/// Applicable to Endpoint only.
#[no_mangle]
pub extern "C" fn quic_config_set_send_batch_size(config: &mut Config, v: u16) {
    config.set_send_batch_size(v as usize);
}

/// Set the buffer size for disordered zerortt packets on the server.
/// The default value is `1000`. A value of 0 will be treated as default value.
/// Applicable to Server only.
#[no_mangle]
pub extern "C" fn quic_config_set_zerortt_buffer_size(config: &mut Config, v: u16) {
    config.set_zerortt_buffer_size(v as usize);
}

/// Set the maximum number of undecryptable packets that can be stored by one connection.
/// The default value is `10`. A value of 0 will be treated as default value.
#[no_mangle]
pub extern "C" fn quic_config_set_max_undecryptable_packets(config: &mut Config, v: u16) {
    config.set_max_undecryptable_packets(v as usize);
}

/// Enable or disable encryption on 1-RTT packets. (Experimental)
/// The default value is true.
/// WARN: The The disable_1rtt_encryption extension is not meant to be used
/// for any practical application protocol on the open internet.
#[no_mangle]
pub extern "C" fn quic_config_enable_encryption(config: &mut Config, v: bool) {
    config.enable_encryption(v);
}

/// Set TLS config selector.
#[no_mangle]
pub extern "C" fn quic_config_set_tls_selector(
    config: &mut Config,
    methods: *const TlsConfigSelectMethods,
    context: TlsConfigSelectorContext,
) {
    let selector = TlsConfigSelector { methods, context };
    config.set_tls_config_selector(Arc::new(selector));
}

/// Set TLS config.
///
/// Note: Config doesn't own the TlsConfig when using this function.
/// It is the responsibility of the caller to release it.
#[no_mangle]
pub extern "C" fn quic_config_set_tls_config(config: &mut Config, tls_config: *mut TlsConfig) {
    if tls_config.is_null() {
        return;
    }

    let tls_config = unsafe { tls_config.as_mut().unwrap() };
    let tls_config = TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx());
    config.set_tls_config(tls_config);
}
