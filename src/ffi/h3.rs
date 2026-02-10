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

use bytes::Bytes;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::h3;
use crate::h3::connection::Http3Connection;
use crate::h3::connection::Http3Priority;
use crate::h3::Http3Config;
use crate::h3::Http3Event;
use crate::h3::Http3Headers;
use crate::h3::NameValue;
use crate::Connection;

/// Create default config for HTTP3.
#[no_mangle]
pub extern "C" fn http3_config_new() -> *mut Http3Config {
    match Http3Config::new() {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy the HTTP3 config.
#[no_mangle]
pub extern "C" fn http3_config_free(config: *mut Http3Config) {
    unsafe {
        let _ = Box::from_raw(config);
    };
}

/// Set the `SETTINGS_MAX_FIELD_SECTION_SIZE` setting.
/// By default no limit is enforced.
#[no_mangle]
pub extern "C" fn http3_config_set_max_field_section_size(config: &mut Http3Config, v: u64) {
    config.set_max_field_section_size(v);
}

/// Set the `SETTINGS_QPACK_MAX_TABLE_CAPACITY` setting.
/// The default value is `0`.
#[no_mangle]
pub extern "C" fn http3_config_set_qpack_max_table_capacity(config: &mut Http3Config, v: u64) {
    config.set_qpack_max_table_capacity(v);
}

/// Set the `SETTINGS_QPACK_BLOCKED_STREAMS` setting.
/// The default value is `0`.
#[no_mangle]
pub extern "C" fn http3_config_set_qpack_blocked_streams(config: &mut Http3Config, v: u64) {
    config.set_qpack_blocked_streams(v);
}

/// Create an HTTP/3 connection using the given QUIC connection. It also
/// initiate the HTTP/3 handshake by opening all control streams and sending
/// the local settings.
#[no_mangle]
pub extern "C" fn http3_conn_new(
    quic_conn: &mut Connection,
    config: &mut Http3Config,
) -> *mut Http3Connection {
    match Http3Connection::new_with_quic_conn(quic_conn, config) {
        Ok(c) => Box::into_raw(Box::new(c)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy the HTTP/3 connection.
#[no_mangle]
pub extern "C" fn http3_conn_free(conn: *mut Http3Connection) {
    unsafe {
        let _ = Box::from_raw(conn);
    };
}

/// Send goaway with the given id.
#[no_mangle]
pub extern "C" fn http3_send_goaway(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    id: u64,
) -> i64 {
    match conn.send_goaway(quic_conn, id) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as i64,
    }
}

/// Set HTTP/3 connection events handler.
#[no_mangle]
pub extern "C" fn http3_conn_set_events_handler(
    conn: &mut Http3Connection,
    methods: *const Http3Methods,
    context: Http3Context,
) {
    let handler = Http3Handler { methods, context };
    conn.set_events_handler(Arc::new(handler));
}

/// Process HTTP/3 settings.
#[no_mangle]
pub extern "C" fn http3_for_each_setting(
    conn: &Http3Connection,
    cb: extern "C" fn(identifier: u64, value: u64, argp: *mut c_void) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.peer_raw_settings() {
        Some(raw) => {
            for setting in raw {
                let rc = cb(setting.0, setting.1, argp);

                if rc != 0 {
                    return rc;
                }
            }
            0
        }

        None => -1,
    }
}

/// Process internal events of all streams of the specified HTTP/3 connection.
#[no_mangle]
pub extern "C" fn http3_conn_process_streams(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
) -> c_int {
    match conn.process_streams(quic_conn) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Process HTTP/3 headers.
#[no_mangle]
pub extern "C" fn http3_for_each_header(
    headers: &Http3Headers,
    cb: extern "C" fn(
        name: *const u8,
        name_len: size_t,
        value: *const u8,
        value_len: size_t,
        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    for h in headers.headers {
        let rc = cb(
            h.name().as_ptr(),
            h.name().len(),
            h.value().as_ptr(),
            h.value().len(),
            argp,
        );
        if rc != 0 {
            return rc;
        }
    }

    0
}

/// Return true if all the data has been read from the stream.
#[no_mangle]
pub extern "C" fn http3_stream_read_finished(conn: &mut Connection, stream_id: u64) -> bool {
    conn.stream_finished(stream_id)
}

/// Create a new HTTP/3 request stream.
/// On success the stream ID is returned.
#[no_mangle]
pub extern "C" fn http3_stream_new(conn: &mut Http3Connection, quic_conn: &mut Connection) -> i64 {
    match conn.stream_new_with_priority(quic_conn, &Http3Priority::default()) {
        Ok(v) => v as i64,
        Err(e) => e.to_errno() as i64,
    }
}

/// Create a new HTTP/3 request stream with the given priority.
/// On success the stream ID is returned.
#[no_mangle]
pub extern "C" fn http3_stream_new_with_priority(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    priority: &Http3Priority,
) -> i64 {
    match conn.stream_new_with_priority(quic_conn, priority) {
        Ok(v) => v as i64,
        Err(e) => e.to_errno() as i64,
    }
}

/// Close the given HTTP/3 stream.
#[no_mangle]
pub extern "C" fn http3_stream_close(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
) -> c_int {
    match conn.stream_close(quic_conn, stream_id) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set priority for an HTTP/3 stream.
#[no_mangle]
pub extern "C" fn http3_stream_set_priority(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    priority: &Http3Priority,
) -> c_int {
    match conn.stream_set_priority(quic_conn, stream_id, priority) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

#[repr(C)]
pub struct Header {
    name: *mut u8,
    name_len: usize,
    value: *mut u8,
    value_len: usize,
}

/// Send HTTP/3 request or response headers on the given stream.
#[no_mangle]
pub extern "C" fn http3_send_headers(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    headers: *const Header,
    headers_len: size_t,
    fin: bool,
) -> c_int {
    let h3_headers = headers_from_ptr(headers, headers_len);

    match conn.send_headers(quic_conn, stream_id, &h3_headers, fin) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send HTTP/3 request or response body on the given stream.
#[no_mangle]
pub extern "C" fn http3_send_body(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    body: *const u8,
    body_len: size_t,
    fin: bool,
) -> ssize_t {
    if body_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let body = unsafe { slice::from_raw_parts(body, body_len) };
    match conn.send_body(quic_conn, stream_id, Bytes::copy_from_slice(body), fin) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno(),
    }
}

/// Read request/response body from the given stream.
#[no_mangle]
pub extern "C" fn http3_recv_body(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    out: *mut u8,
    out_len: size_t,
) -> ssize_t {
    if out_len > <ssize_t>::MAX as usize {
        panic!("The provided buffer is too large");
    }

    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    match conn.recv_body(quic_conn, stream_id, out) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno(),
    }
}

/// Parse HTTP/3 priority data.
#[no_mangle]
pub extern "C" fn http3_parse_extensible_priority(
    priority: *const u8,
    priority_len: size_t,
    parsed: &mut Http3Priority,
) -> c_int {
    let priority = unsafe { slice::from_raw_parts(priority, priority_len) };

    match Http3Priority::try_from(priority) {
        Ok(v) => {
            parsed.urgency = v.urgency;
            parsed.incremental = v.incremental;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send a PRIORITY_UPDATE frame on the control stream with specified
/// request stream ID and priority.
#[no_mangle]
pub extern "C" fn http3_send_priority_update_for_request(
    conn: &mut Http3Connection,
    quic_conn: &mut Connection,
    stream_id: u64,
    priority: &Http3Priority,
) -> c_int {
    match conn.send_priority_update_for_request(quic_conn, stream_id, priority) {
        Ok(()) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Take the last PRIORITY_UPDATE for the given stream.
#[no_mangle]
pub extern "C" fn http3_take_priority_update(
    conn: &mut Http3Connection,
    prioritized_element_id: u64,
    cb: extern "C" fn(
        priority_field_value: *const u8,
        priority_field_value_len: size_t,
        argp: *mut c_void,
    ) -> c_int,
    argp: *mut c_void,
) -> c_int {
    match conn.take_priority_update(prioritized_element_id) {
        Ok(priority) => {
            let rc = cb(priority.as_ptr(), priority.len(), argp);
            if rc != 0 {
                return rc;
            }
            0
        }

        Err(e) => e.to_errno() as c_int,
    }
}

/// Convert HTTP/3 header.
fn headers_from_ptr<'a>(ptr: *const Header, len: size_t) -> Vec<h3::HeaderRef<'a>> {
    let headers = unsafe { slice::from_raw_parts(ptr, len) };

    let mut out = Vec::new();
    for h in headers {
        out.push({
            let name = unsafe { slice::from_raw_parts(h.name, h.name_len) };
            let value = unsafe { slice::from_raw_parts(h.value, h.value_len) };
            h3::HeaderRef::new(name, value)
        });
    }

    out
}

// --- Http3Handler types ---

#[repr(C)]
pub struct Http3Methods {
    /// Called when the stream got headers.
    pub on_stream_headers:
        Option<fn(ctx: *mut c_void, stream_id: u64, headers: &Http3Headers, fin: bool)>,

    /// Called when the stream has buffered data to read.
    pub on_stream_data: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the stream is finished.
    pub on_stream_finished: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the stream receives a RESET_STREAM frame from the peer.
    pub on_stream_reset: Option<fn(ctx: *mut c_void, stream_id: u64, error_code: u64)>,

    /// Called when the stream priority is updated.
    pub on_stream_priority_update: Option<fn(ctx: *mut c_void, stream_id: u64)>,

    /// Called when the connection receives a GOAWAY frame from the peer.
    pub on_conn_goaway: Option<fn(ctx: *mut c_void, stream_id: u64)>,
}

#[repr(transparent)]
pub struct Http3Context(*mut c_void);

#[repr(C)]
pub struct Http3Handler {
    pub methods: *const Http3Methods,
    pub context: Http3Context,
}

unsafe impl Send for Http3Handler {}
unsafe impl Sync for Http3Handler {}

impl crate::h3::Http3Handler for Http3Handler {
    fn on_stream_headers(&self, stream_id: u64, ev: &mut Http3Event) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_headers {
                let (headers, fin) = match ev {
                    Http3Event::Headers { headers, fin } => (Http3Headers { headers }, *fin),
                    _ => unreachable!(),
                };

                f(self.context.0, stream_id, &headers, fin);
            }
        }
    }

    fn on_stream_data(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_data {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_stream_finished(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_finished {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_stream_reset(&self, stream_id: u64, error_code: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_reset {
                f(self.context.0, stream_id, error_code);
            }
        }
    }

    fn on_stream_priority_update(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_priority_update {
                f(self.context.0, stream_id);
            }
        }
    }

    fn on_conn_goaway(&self, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_goaway {
                f(self.context.0, stream_id);
            }
        }
    }
}
