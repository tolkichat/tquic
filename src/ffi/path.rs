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

use libc::c_int;
use libc::c_void;
use libc::sockaddr;

use crate::Connection;

use super::sock_addr_from_c;
use super::socklen_t;
use super::Context;

/// Add a new path on the client connection.
#[no_mangle]
pub extern "C" fn quic_conn_add_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
    index: *mut u64,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.add_path(local, remote) {
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

/// Remove a path on the client connection.
#[no_mangle]
pub extern "C" fn quic_conn_abandon_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.abandon_path(local, remote) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Migrate the client connection to the specified path.
#[no_mangle]
pub extern "C" fn quic_conn_migrate_path(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> c_int {
    let local = sock_addr_from_c(local, local_len);
    let remote = sock_addr_from_c(remote, remote_len);

    match conn.migrate_path(local, remote) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as i32,
    }
}

/// Set peer context for the specified path.
#[no_mangle]
pub extern "C" fn quic_path_set_peer_context(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
    data: *mut c_void,
) -> c_int {
    let local_addr = sock_addr_from_c(local, local_len);
    let remote_addr = sock_addr_from_c(remote, remote_len);
    match conn.set_path_peer_context(local_addr, remote_addr, Context(data)) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Get peer context for the specified path.
#[no_mangle]
pub extern "C" fn quic_path_peer_context(
    conn: &mut Connection,
    local: &sockaddr,
    local_len: socklen_t,
    remote: &sockaddr,
    remote_len: socklen_t,
) -> *mut c_void {
    let local_addr = sock_addr_from_c(local, local_len);
    let remote_addr = sock_addr_from_c(remote, remote_len);
    match conn.path_peer_context(local_addr, remote_addr) {
        Ok(Some(v)) => v.downcast_mut::<Context>().unwrap().0,
        _ => ptr::null_mut(),
    }
}
