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
use std::sync::atomic;

#[cfg(unix)]
use std::os::fd::FromRawFd;

use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::sockaddr;

use crate::connection::ConnectionStats;
use crate::Connection;
use crate::FourTuple;
use crate::PathStats;

use super::sock_addr_from_c;
use super::sock_addr_to_c;
use super::socklen_t;
use super::Context;
use super::LogWriter;
use crate::FourTupleIter;
use super::PathAddress;

/// Get index of the connection
#[no_mangle]
pub extern "C" fn quic_conn_index(conn: &mut Connection) -> u64 {
    conn.index().unwrap_or(u64::MAX)
}

/// Check whether the connection is a server connection.
#[no_mangle]
pub extern "C" fn quic_conn_is_server(conn: &mut Connection) -> bool {
    conn.is_server()
}

/// Check whether the connection handshake is complete.
#[no_mangle]
pub extern "C" fn quic_conn_is_established(conn: &mut Connection) -> bool {
    conn.is_established()
}

/// Check whether the connection is created by a resumed handshake.
#[no_mangle]
pub extern "C" fn quic_conn_is_resumed(conn: &mut Connection) -> bool {
    conn.is_resumed()
}

/// Check whether the connection has a pending handshake that has progressed
/// enough to send or receive early data.
#[no_mangle]
pub extern "C" fn quic_conn_is_in_early_data(conn: &mut Connection) -> bool {
    conn.is_in_early_data()
}

/// Check whether the established connection works in multipath mode.
#[no_mangle]
pub extern "C" fn quic_conn_is_multipath(conn: &mut Connection) -> bool {
    conn.is_multipath()
}

/// Return the negotiated application level protocol.
#[no_mangle]
pub extern "C" fn quic_conn_application_proto(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    let proto = conn.application_proto();
    *out = proto.as_ptr();
    *out_len = proto.len();
}

/// Return the server name in the TLS SNI extension.
#[no_mangle]
pub extern "C" fn quic_conn_server_name(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    if let Some(name) = conn.server_name() {
        *out = name.as_ptr();
        *out_len = name.len();
    } else {
        *out = ptr::null_mut();
        *out_len = 0;
    }
}

/// Return the session data used by resumption.
#[no_mangle]
pub extern "C" fn quic_conn_session(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    match conn.session() {
        Some(session) => {
            *out = session.as_ptr();
            *out_len = session.len();
        }
        None => *out_len = 0,
    }
}

/// Return details why 0-RTT was accepted or rejected.
#[no_mangle]
pub extern "C" fn quic_conn_early_data_reason(conn: &mut Connection) -> c_int {
    conn.early_data_reason() as c_int
}

/// Return a string representation for reason why 0-RTT was accepted or rejected.
#[no_mangle]
pub extern "C" fn quic_conn_early_data_reason_string(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) -> c_int {
    match conn.early_data_reason_string() {
        Ok(reason) => {
            match reason {
                Some(reason) => {
                    *out = reason.as_ptr();
                    *out_len = reason.len();
                }
                None => *out_len = 0,
            }
            0
        }
        Err(e) => e.to_errno() as i32,
    }
}

/// Return statistics about the connection.
#[no_mangle]
pub extern "C" fn quic_conn_stats(conn: &mut Connection) -> &ConnectionStats {
    conn.stats()
}

/// Return the trace id of the connection
#[no_mangle]
pub extern "C" fn quic_conn_trace_id(
    conn: &mut Connection,
    out: &mut *const u8,
    out_len: &mut size_t,
) {
    let id = conn.trace_id();
    *out = id.as_ptr();
    *out_len = id.len();
}

/// Check whether the connection is draining.
#[no_mangle]
pub extern "C" fn quic_conn_is_draining(conn: &mut Connection) -> bool {
    conn.is_draining()
}

/// Check whether the connection is closing.
#[no_mangle]
pub extern "C" fn quic_conn_is_closing(conn: &mut Connection) -> bool {
    conn.is_closing()
}

/// Check whether the connection is closed.
#[no_mangle]
pub extern "C" fn quic_conn_is_closed(conn: &mut Connection) -> bool {
    conn.is_closed()
}

/// Check whether the connection was closed due to handshake timeout.
#[no_mangle]
pub extern "C" fn quic_conn_is_handshake_timeout(conn: &mut Connection) -> bool {
    conn.is_handshake_timeout()
}

/// Check whether the connection was closed due to idle timeout.
#[no_mangle]
pub extern "C" fn quic_conn_is_idle_timeout(conn: &mut Connection) -> bool {
    conn.is_idle_timeout()
}

/// Check whether the connection was closed due to stateless reset.
#[no_mangle]
pub extern "C" fn quic_conn_is_reset(conn: &mut Connection) -> bool {
    conn.is_reset()
}

/// Returns the error from the peer, if any.
#[no_mangle]
pub extern "C" fn quic_conn_peer_error(
    conn: &mut Connection,
    is_app: *mut bool,
    error_code: *mut u64,
    reason: &mut *const u8,
    reason_len: &mut size_t,
) -> bool {
    match &conn.peer_error() {
        Some(conn_err) => unsafe {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();
            true
        },
        None => false,
    }
}

/// Returns the local error, if any.
#[no_mangle]
pub extern "C" fn quic_conn_local_error(
    conn: &mut Connection,
    is_app: *mut bool,
    error_code: *mut u64,
    reason: &mut *const u8,
    reason_len: &mut size_t,
) -> bool {
    match &conn.local_error() {
        Some(conn_err) => unsafe {
            *is_app = conn_err.is_app;
            *error_code = conn_err.error_code;
            *reason = conn_err.reason.as_ptr();
            *reason_len = conn_err.reason.len();
            true
        },
        None => false,
    }
}

/// Set user context for the connection.
#[no_mangle]
pub extern "C" fn quic_conn_set_context(conn: &mut Connection, data: *mut c_void) {
    conn.set_context(Context(data))
}

/// Get user context for the connection.
#[no_mangle]
pub extern "C" fn quic_conn_context(conn: &mut Connection) -> *mut c_void {
    match conn.context() {
        Some(v) => v.downcast_mut::<Context>().unwrap().0,
        None => ptr::null_mut(),
    }
}

/// Set the callback of keylog output.
/// `cb` is a callback function that will be called for each keylog.
/// `data` is a keylog message and `argp` is user-defined data that will be passed to the callback.
#[no_mangle]
pub extern "C" fn quic_conn_set_keylog(
    conn: &mut Connection,
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let writer = Box::new(LogWriter { cb, argp });
    conn.set_keylog(Box::new(writer));
}

/// Set keylog file.
/// Note: The API is not applicable for Windows.
#[no_mangle]
#[cfg(unix)]
pub extern "C" fn quic_conn_set_keylog_fd(conn: &mut Connection, fd: c_int) {
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(file);
    conn.set_keylog(Box::new(writer));
}

/// Set the callback of qlog output.
/// `cb` is a callback function that will be called for each qlog.
/// `data` is a qlog message and `argp` is user-defined data that will be passed to the callback.
/// `title` and `desc` respectively refer to the "title" and "description" sections of qlog.
#[no_mangle]
#[cfg(feature = "qlog")]
pub extern "C" fn quic_conn_set_qlog(
    conn: &mut Connection,
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
    title: *const libc::c_char,
    desc: *const libc::c_char,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let writer = Box::new(LogWriter { cb, argp });
    let title = unsafe { std::ffi::CStr::from_ptr(title).to_str().unwrap() };
    let description = unsafe { std::ffi::CStr::from_ptr(desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id()),
    );
}

/// Set qlog file.
/// Note: The API is not applicable for Windows.
#[no_mangle]
#[cfg(feature = "qlog")]
#[cfg(unix)]
pub extern "C" fn quic_conn_set_qlog_fd(
    conn: &mut Connection,
    fd: c_int,
    title: *const libc::c_char,
    desc: *const libc::c_char,
) {
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let writer = std::io::BufWriter::new(file);
    let title = unsafe { std::ffi::CStr::from_ptr(title).to_str().unwrap() };
    let description = unsafe { std::ffi::CStr::from_ptr(desc).to_str().unwrap() };

    conn.set_qlog(
        Box::new(writer),
        title.to_string(),
        format!("{} id={}", description, conn.trace_id()),
    );
}

/// Close the connection.
#[no_mangle]
pub extern "C" fn quic_conn_close(
    conn: &mut Connection,
    app: bool,
    err: u64,
    reason: *const u8,
    reason_len: size_t,
) -> c_int {
    let reason = unsafe { slice::from_raw_parts(reason, reason_len) };
    match conn.close(app, err, reason) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send a Ping frame on the active path(s) for keep-alive.
#[no_mangle]
pub extern "C" fn quic_conn_ping(conn: &mut Connection) -> c_int {
    match conn.ping(None) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Send a Ping frame on the specified path for keep-alive.
/// The API is only applicable to multipath quic connections.
#[no_mangle]
pub extern "C" fn quic_conn_ping_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> c_int {
    let addr = FourTuple {
        local: sock_addr_from_c(local, local_len),
        remote: sock_addr_from_c(remote, remote_len),
    };
    match conn.ping(Some(addr)) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Return an iterator over path addresses.
/// The caller should properly destroy it by calling `quic_four_tuple_iter_free`.
#[no_mangle]
pub extern "C" fn quic_conn_paths(conn: &mut Connection) -> *mut FourTupleIter {
    let iter = Box::new(conn.paths_iter());
    Box::into_raw(iter)
}

/// Destroy the FourTupleIter
#[no_mangle]
pub extern "C" fn quic_conn_path_iter_free(iter: *mut FourTupleIter) {
    unsafe {
        let _ = Box::from_raw(iter);
    };
}

/// Return the address of the next path.
#[no_mangle]
pub extern "C" fn quic_conn_path_iter_next(iter: &mut FourTupleIter, a: &mut PathAddress) -> bool {
    if let Some(v) = iter.next() {
        a.local_addr_len = sock_addr_to_c(&v.local, &mut a.local_addr);
        a.remote_addr_len = sock_addr_to_c(&v.remote, &mut a.remote_addr);
        return true;
    }
    false
}

/// Return the address of the active path
#[no_mangle]
pub extern "C" fn quic_conn_active_path(conn: &Connection, a: &mut PathAddress) -> bool {
    if let Ok(v) = conn.get_active_path() {
        a.local_addr_len = sock_addr_to_c(&v.local_addr(), &mut a.local_addr);
        a.remote_addr_len = sock_addr_to_c(&v.remote_addr(), &mut a.remote_addr);
        return true;
    }
    false
}

/// Return the latest statistics about the specified path.
#[no_mangle]
pub extern "C" fn quic_conn_path_stats<'a>(
    conn: &'a mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> Option<&'a PathStats> {
    let local_addr = sock_addr_from_c(local, local_len);
    let remote_addr = sock_addr_from_c(remote, remote_len);
    if let Ok(stats) = conn.get_path_stats(local_addr, remote_addr) {
        return Some(stats);
    }
    None
}
