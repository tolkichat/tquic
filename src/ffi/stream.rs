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

use bytes::Bytes;
use libc::c_int;
use libc::c_void;
use libc::size_t;
use libc::ssize_t;

use crate::error::Error;
use crate::Connection;
use crate::Shutdown;

use super::Context;

/// Set want write flag for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_wantwrite(
    conn: &mut Connection,
    stream_id: u64,
    want: bool,
) -> c_int {
    match conn.stream_want_write(stream_id, want) {
        Ok(_) | Err(Error::Done) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set want read flag for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_wantread(conn: &mut Connection, stream_id: u64, want: bool) -> c_int {
    match conn.stream_want_read(stream_id, want) {
        Ok(_) | Err(Error::Done) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Read data from a stream.
#[no_mangle]
pub extern "C" fn quic_stream_read(
    conn: &mut Connection,
    stream_id: u64,
    out: *mut u8,
    out_len: size_t,
    fin: &mut bool,
) -> ssize_t {
    let out = unsafe { slice::from_raw_parts_mut(out, out_len) };
    let (out_len, out_fin) = match conn.stream_read(stream_id, out) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    *fin = out_fin;
    out_len as ssize_t
}

/// Write data to a stream.
#[no_mangle]
pub extern "C" fn quic_stream_write(
    conn: &mut Connection,
    stream_id: u64,
    buf: *const u8,
    buf_len: size_t,
    fin: bool,
) -> ssize_t {
    let buf = unsafe { slice::from_raw_parts(buf, buf_len) };
    let buf = Bytes::copy_from_slice(buf);
    match conn.stream_write(stream_id, buf, fin) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno() as ssize_t,
    }
}

/// Create a new quic stream with the given id and priority.
/// This is a low-level API for stream creation. It is recommended to use
/// `quic_stream_bidi_new` for bidirectional streams or `quic_stream_uni_new`
/// for undirectional streams.
#[no_mangle]
pub extern "C" fn quic_stream_new(
    conn: &mut Connection,
    stream_id: u64,
    urgency: u8,
    incremental: bool,
) -> c_int {
    match conn.stream_new(stream_id, urgency, incremental) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Create a new quic bidiectional stream with the given priority.
/// If success, the output parameter `stream_id` carrys the id of the created stream.
#[no_mangle]
pub extern "C" fn quic_stream_bidi_new(
    conn: &mut Connection,
    urgency: u8,
    incremental: bool,
    stream_id: &mut u64,
) -> c_int {
    match conn.stream_bidi_new(urgency, incremental) {
        Ok(id) => {
            *stream_id = id;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Create a new quic uniectional stream with the given priority.
/// If success, the output parameter `stream_id` carrys the id of the created stream.
#[no_mangle]
pub extern "C" fn quic_stream_uni_new(
    conn: &mut Connection,
    urgency: u8,
    incremental: bool,
    stream_id: &mut u64,
) -> c_int {
    match conn.stream_uni_new(urgency, incremental) {
        Ok(id) => {
            *stream_id = id;
            0
        }
        Err(e) => e.to_errno() as c_int,
    }
}

/// Shutdown stream reading or writing.
#[no_mangle]
pub extern "C" fn quic_stream_shutdown(
    conn: &mut Connection,
    stream_id: u64,
    direction: Shutdown,
    err: u64,
) -> c_int {
    match conn.stream_shutdown(stream_id, direction, err) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the priority for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_set_priority(
    conn: &mut Connection,
    stream_id: u64,
    urgency: u8,
    incremental: bool,
) -> c_int {
    match conn.stream_set_priority(stream_id, urgency, incremental) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Return the stream's send capacity in bytes.
#[no_mangle]
pub extern "C" fn quic_stream_capacity(conn: &mut Connection, stream_id: u64) -> ssize_t {
    match conn.stream_capacity(stream_id) {
        Ok(v) => v as ssize_t,
        Err(e) => e.to_errno() as ssize_t,
    }
}

/// Return true if all the data has been read from the stream.
#[no_mangle]
pub extern "C" fn quic_stream_finished(conn: &mut Connection, stream_id: u64) -> bool {
    conn.stream_finished(stream_id)
}

/// Set user context for a stream.
#[no_mangle]
pub extern "C" fn quic_stream_set_context(
    conn: &mut Connection,
    stream_id: u64,
    data: *mut c_void,
) -> c_int {
    match conn.stream_set_context(stream_id, Context(data)) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Return the stream's user context.
#[no_mangle]
pub extern "C" fn quic_stream_context(conn: &mut Connection, stream_id: u64) -> *mut c_void {
    match conn.stream_context(stream_id) {
        Some(v) => v.downcast_mut::<Context>().unwrap().0,
        None => ptr::null_mut(),
    }
}
