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

use std::mem;

use libc::c_void;
use libc::size_t;

use crate::error::Error;
use crate::Connection;
use crate::ConnectionId;
use crate::Result;

use super::iovec;
use super::sock_addr_to_c;
use super::sockaddr_storage;
use super::socklen_t;
use super::PacketOutSpec;

// --- TransportHandler ---

#[repr(C)]
pub struct TransportMethods {
    /// Called when a new connection has been created. This callback is called
    /// as soon as connection object is created inside the endpoint, but
    /// before the handshake is done. This callback is optional.
    pub on_conn_created: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the handshake is completed. This callback is optional.
    pub on_conn_established: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the connection is closed. The connection is no longer
    /// accessible after this callback returns. It is a good time to clean up
    /// the connection context. This callback is optional.
    pub on_conn_closed: Option<fn(tctx: *mut c_void, conn: &mut Connection)>,

    /// Called when the stream is created. This callback is optional.
    pub on_stream_created: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is readable. This callback is called when either
    /// there are bytes to be read or an error is ready to be collected. This
    /// callback is optional.
    pub on_stream_readable: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is writable. This callback is optional.
    pub on_stream_writable: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when the stream is closed. The stream is no longer accessible
    /// after this callback returns. It is a good time to clean up the stream
    /// context. This callback is optional.
    pub on_stream_closed: Option<fn(tctx: *mut c_void, conn: &mut Connection, stream_id: u64)>,

    /// Called when client receives a token in NEW_TOKEN frame. This callback
    /// is optional.
    pub on_new_token:
        Option<fn(tctx: *mut c_void, conn: &mut Connection, token: *const u8, token_len: size_t)>,
}

#[repr(transparent)]
pub struct TransportContext(pub(crate) *mut c_void);

/// cbindgen:no-export
#[repr(C)]
pub struct TransportHandler {
    pub methods: *const TransportMethods,
    pub context: TransportContext,
}

impl crate::TransportHandler for TransportHandler {
    fn on_conn_created(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_created {
                f(self.context.0, conn);
            }
        }
    }

    fn on_conn_established(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_established {
                f(self.context.0, conn);
            }
        }
    }

    fn on_conn_closed(&mut self, conn: &mut Connection) {
        unsafe {
            if let Some(f) = (*self.methods).on_conn_closed {
                f(self.context.0, conn);
            }
        }
    }

    fn on_stream_created(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_created {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_readable(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_readable {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_writable(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_writable {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_stream_closed(&mut self, conn: &mut Connection, stream_id: u64) {
        unsafe {
            if let Some(f) = (*self.methods).on_stream_closed {
                f(self.context.0, conn, stream_id);
            }
        }
    }

    fn on_new_token(&mut self, conn: &mut Connection, token: Vec<u8>) {
        let token_len = token.len() as size_t;
        let token = token.as_ptr();
        unsafe {
            if let Some(f) = (*self.methods).on_new_token {
                f(self.context.0, conn, token, token_len);
            }
        }
    }
}

// --- PacketSendHandler ---

#[repr(C)]
pub struct PacketSendMethods {
    /// Called when the connection is sending packets out.
    /// On success, `on_packets_send()` returns the number of messages sent. If
    /// this is less than count, the connection will retry with a further
    /// `on_packets_send()` call to send the remaining messages. This callback
    /// is mandatory.
    pub on_packets_send:
        fn(psctx: *mut c_void, pkts: *mut PacketOutSpec, count: libc::c_uint) -> libc::c_int,
}

#[repr(transparent)]
pub struct PacketSendContext(pub(crate) *mut c_void);

/// cbindgen:no-export
#[repr(C)]
pub struct PacketSendHandler {
    pub methods: *const PacketSendMethods,
    pub context: PacketSendContext,
}

impl crate::PacketSendHandler for PacketSendHandler {
    #[allow(clippy::comparison_chain)]
    fn on_packets_send(&self, pkts: &[(Vec<u8>, crate::PacketInfo)]) -> Result<usize> {
        let mut pkt_specs: Vec<PacketOutSpec> = Vec::with_capacity(pkts.len());
        let mut iovecs: Vec<iovec> = Vec::with_capacity(pkts.len());
        let mut src_addrs: Vec<sockaddr_storage> = Vec::with_capacity(pkts.len());
        let mut dst_addrs: Vec<sockaddr_storage> = Vec::with_capacity(pkts.len());

        // Prepare packets to be send
        for (i, (pkt, info)) in pkts.iter().enumerate() {
            let iov = iovec {
                iov_base: pkt.as_ptr() as *mut c_void,
                iov_len: pkt.len(),
            };
            let mut src_addr: sockaddr_storage = unsafe { mem::zeroed() };
            let src_addr_len = sock_addr_to_c(&info.src, &mut src_addr);
            let mut dst_addr: sockaddr_storage = unsafe { mem::zeroed() };
            let dst_addr_len = sock_addr_to_c(&info.dst, &mut dst_addr);

            iovecs.push(iov);
            src_addrs.push(src_addr);
            dst_addrs.push(dst_addr);

            let pkt_spec = PacketOutSpec {
                iov: &iovecs[i] as *const _ as *mut _,
                iovlen: 1,
                src_addr: &src_addrs[i] as *const _ as *const c_void,
                src_addr_len,
                dst_addr: &dst_addrs[i] as *const _ as *const c_void,
                dst_addr_len,
            };

            pkt_specs.push(pkt_spec);
        }

        // Send packets out
        let count = unsafe {
            ((*self.methods).on_packets_send)(
                self.context.0,
                pkt_specs.as_mut_ptr(),
                pkts.len() as libc::c_uint,
            )
        };
        if count > 0 {
            Ok(count as usize)
        } else if count == 0 {
            Err(Error::Done)
        } else {
            Err(Error::InternalError)
        }
    }
}

// --- ConnectionIdGenerator ---

#[repr(C)]
pub struct ConnectionIdGeneratorMethods {
    /// Generate a new CID
    pub generate: fn(gctx: *mut c_void) -> ConnectionId,

    /// Return the length of a CID
    pub cid_len: fn(gctx: *mut c_void) -> u8,
}

#[repr(transparent)]
pub struct ConnectionIdGeneratorContext(pub(crate) *mut c_void);

/// cbindgen:no-export
#[repr(C)]
pub struct ConnectionIdGenerator {
    pub methods: *const ConnectionIdGeneratorMethods,
    pub context: ConnectionIdGeneratorContext,
}

impl crate::ConnectionIdGenerator for ConnectionIdGenerator {
    /// Generate a new CID
    fn generate(&mut self) -> ConnectionId {
        unsafe { ((*self.methods).generate)(self.context.0) }
    }

    /// Return the length of a CID
    fn cid_len(&self) -> usize {
        let cid_len = unsafe { ((*self.methods).cid_len)(self.context.0) };
        cid_len as usize
    }
}
