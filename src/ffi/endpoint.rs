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

use std::ffi;
use std::ptr;
use std::slice;
use std::time::Instant;

use crate::SharedRc;

use libc::c_char;
use libc::c_int;
use libc::size_t;

use crate::Config;
use crate::Connection;
use crate::ConnectionId;
use crate::Endpoint;

use super::handler::ConnectionIdGenerator;
use super::handler::ConnectionIdGeneratorContext;
use super::handler::ConnectionIdGeneratorMethods;
use super::handler::PacketSendContext;
use super::handler::PacketSendHandler;
use super::handler::PacketSendMethods;
use super::handler::TransportContext;
use super::handler::TransportHandler;
use super::handler::TransportMethods;
use super::sock_addr_from_c;
use super::socklen_t;
use super::PacketInfo;

/// Create a QUIC endpoint.
///
/// The caller is responsible for the memory of the Endpoint and properly
/// destroy it by calling `quic_endpoint_free`.
///
/// Note: The endpoint doesn't own the underlying resources provided by the C
/// caller. It is the responsibility of the caller to ensure that these
/// resources outlive the endpoint and release them correctly.
#[no_mangle]
pub extern "C" fn quic_endpoint_new(
    config: *mut Config,
    is_server: bool,
    handler_methods: *const TransportMethods,
    handler_ctx: TransportContext,
    sender_methods: *const PacketSendMethods,
    sender_ctx: PacketSendContext,
) -> *mut Endpoint {
    let config = unsafe { Box::from_raw(config) };
    let handler = Box::new(TransportHandler {
        methods: handler_methods,
        context: handler_ctx,
    });
    let sender = SharedRc::new(PacketSendHandler {
        methods: sender_methods,
        context: sender_ctx,
    });
    let e = Endpoint::new(config.clone(), is_server, handler, sender);
    let _ = Box::into_raw(config);
    Box::into_raw(Box::new(e))
}

/// Destroy a QUIC endpoint.
#[no_mangle]
pub extern "C" fn quic_endpoint_free(endpoint: *mut Endpoint) {
    unsafe {
        let _ = Box::from_raw(endpoint);
    };
}

/// Set the connection id generator for the endpoint.
/// By default, the random connection id generator is used.
#[no_mangle]
pub extern "C" fn quic_endpoint_set_cid_generator(
    endpoint: &mut Endpoint,
    cid_gen_methods: *const ConnectionIdGeneratorMethods,
    cid_gen_ctx: ConnectionIdGeneratorContext,
) {
    let cid_generator = Box::new(ConnectionIdGenerator {
        methods: cid_gen_methods,
        context: cid_gen_ctx,
    });
    endpoint.set_cid_generator(cid_generator);
}

/// Create a client connection.
/// If success, the output parameter `index` carrys the index of the connection.
/// Note: The `config` specific to the endpoint or server is irrelevant and will be disregarded.
#[no_mangle]
pub extern "C" fn quic_endpoint_connect(
    endpoint: &mut Endpoint,
    local: &libc::sockaddr,
    local_len: socklen_t,
    remote: &libc::sockaddr,
    remote_len: socklen_t,
    server_name: *const c_char,
    session: *const u8,
    session_len: size_t,
    token: *const u8,
    token_len: size_t,
    config: *const Config,
    index: *mut u64,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    let server_name = if !server_name.is_null() {
        Some(unsafe {
            ffi::CStr::from_ptr(server_name)
                .to_str()
                .unwrap_or_default()
        })
    } else {
        None
    };

    let session = if session_len > 0 {
        Some(unsafe { slice::from_raw_parts(session, session_len) })
    } else {
        None
    };
    let token = if token_len > 0 {
        Some(unsafe { slice::from_raw_parts(token, token_len) })
    } else {
        None
    };
    let config = if !config.is_null() {
        Some(unsafe { &(*config) })
    } else {
        None
    };

    match endpoint.connect(local, remote, server_name, session, token, config) {
        Ok(idx) => {
            if !index.is_null() {
                unsafe {
                    *index = idx;
                }
            }
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}

/// Process an incoming UDP datagram.
#[no_mangle]
pub extern "C" fn quic_endpoint_recv(
    endpoint: &mut Endpoint,
    buf: *mut u8,
    buf_len: size_t,
    info: &PacketInfo,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    let info: crate::PacketInfo = info.into();
    match endpoint.recv(buf, &info) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Return the amount of time until the next timeout event.
#[no_mangle]
pub extern "C" fn quic_endpoint_timeout(endpoint: &Endpoint) -> u64 {
    match endpoint.timeout() {
        Some(v) => v.as_millis() as u64,
        None => u64::MAX,
    }
}

/// Process timeout events on the endpoint.
#[no_mangle]
pub extern "C" fn quic_endpoint_on_timeout(endpoint: &mut Endpoint) {
    let now = Instant::now();
    endpoint.on_timeout(now);
}

/// Process internal events of all tickable connections.
#[no_mangle]
pub extern "C" fn quic_endpoint_process_connections(endpoint: &mut Endpoint) -> c_int {
    match endpoint.process_connections() {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Check whether the given connection exists.
#[no_mangle]
pub extern "C" fn quic_endpoint_exist_connection(
    endpoint: &mut Endpoint,
    cid: *const u8,
    cid_len: size_t,
) -> bool {
    let cid = unsafe { slice::from_raw_parts(cid, cid_len) };
    endpoint.conn_exist(ConnectionId::new(cid))
}

/// Get the connection by index
#[no_mangle]
pub extern "C" fn quic_endpoint_get_connection(
    endpoint: &mut Endpoint,
    index: u64,
) -> *mut Connection {
    match endpoint.conn_get_mut(index) {
        Some(v) => v,
        None => ptr::null_mut(),
    }
}

/// Gracefully or forcibly shutdown the endpoint.
/// If `force` is false, cease creating new connections and wait for all
/// active connections to close. Otherwise, forcibly close all the active
/// connections.
#[no_mangle]
pub extern "C" fn quic_endpoint_close(endpoint: &mut Endpoint, force: bool) {
    endpoint.close(force)
}

/// Extract the header form, version and destination connection id from the
/// QUIC packet.
#[no_mangle]
pub extern "C" fn quic_packet_header_info(
    buf: *mut u8,
    buf_len: size_t,
    dcid_len: u8,
    long_header: &mut bool,
    version: &mut u32,
    dcid: &mut ConnectionId,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts_mut(buf, buf_len) };

    match crate::PacketHeader::header_info(buf, dcid_len as usize) {
        Ok((long, ver, cid)) => {
            *long_header = long;
            *version = ver;
            *dcid = cid;
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}
