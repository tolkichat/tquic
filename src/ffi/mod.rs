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

// Note: The API is not stable and may change in future versions.

mod config;
mod connection;
mod endpoint;
mod handler;
mod path;
mod stream;
mod tls_config;

#[cfg(feature = "h3")]
mod h3;

use std::ffi;
use std::io::Write;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::str::FromStr;
use std::sync::atomic;

use libc::c_char;
use libc::c_void;
use libc::size_t;
use libc::sockaddr;
use libc::ssize_t;

#[cfg(not(windows))]
use libc::in_addr;
#[cfg(windows)]
use winapi::shared::inaddr::IN_ADDR as in_addr;

#[cfg(not(windows))]
use libc::in6_addr;
#[cfg(windows)]
use winapi::shared::in6addr::IN6_ADDR as in6_addr;

#[cfg(not(windows))]
use libc::sa_family_t;
#[cfg(windows)]
use winapi::shared::ws2def::ADDRESS_FAMILY as sa_family_t;

#[cfg(not(windows))]
use libc::sockaddr_in;
#[cfg(windows)]
use winapi::shared::ws2def::SOCKADDR_IN as sockaddr_in;

#[cfg(not(windows))]
use libc::sockaddr_in6;
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH as sockaddr_in6;

#[cfg(not(windows))]
use libc::sockaddr_storage;
#[cfg(windows)]
use winapi::shared::ws2def::SOCKADDR_STORAGE_LH as sockaddr_storage;

#[cfg(windows)]
use libc::c_int as socklen_t;
#[cfg(not(windows))]
use libc::socklen_t;

#[cfg(not(windows))]
use libc::AF_INET;
#[cfg(windows)]
use winapi::shared::ws2def::AF_INET;

#[cfg(not(windows))]
use libc::AF_INET6;
#[cfg(windows)]
use winapi::shared::ws2def::AF_INET6;

#[cfg(windows)]
use winapi::shared::in6addr::in6_addr_u;
#[cfg(windows)]
use winapi::shared::inaddr::in_addr_S_un;
#[cfg(windows)]
use winapi::shared::ws2ipdef::SOCKADDR_IN6_LH_u;

#[cfg(not(windows))]
use libc::iovec;

/// cbindgen:ignore
#[cfg(windows)]
#[allow(non_camel_case_types)]
#[repr(C)]
pub struct iovec {
    iov_base: *mut c_void, // starting address
    iov_len: size_t,       // number of bytes to transfer
}

/// Certificate compression algorithm types for C API compatibility.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum CertCompressionAlgorithm {
    /// zlib compression (RFC 1950)
    Zlib = 1,
    /// Brotli compression (RFC 7932)
    Brotli = 2,
    /// Zstandard compression (RFC 8478)
    Zstd = 3,
}

/// Check whether the protocol version is supported.
#[no_mangle]
pub extern "C" fn quic_version_is_supported(version: u32) -> bool {
    crate::version_is_supported(version)
}

struct LogWriter {
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: std::sync::atomic::AtomicPtr<c_void>,
}

impl Write for LogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.cb)(
            buf.as_ptr(),
            buf.len(),
            self.argp.load(atomic::Ordering::Relaxed),
        );
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl log::Log for LogWriter {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let line = format!("{}: {}\n", record.target(), record.args());
        (self.cb)(
            line.as_ptr(),
            line.len(),
            self.argp.load(atomic::Ordering::Relaxed),
        );
    }

    fn flush(&self) {}
}

/// Set logger.
/// `cb` is a callback function that will be called for each log message.
/// `data` is a '\n' terminated log message and `argp` is user-defined data that
/// will be passed to the callback.
/// `level` is a case-insensitive string used for specifying the log level. Valid
/// values are "OFF", "ERROR", "WARN", "INFO", "DEBUG", and "TRACE". If its value
/// is NULL or invalid, the default log level is "OFF".
#[no_mangle]
pub extern "C" fn quic_set_logger(
    cb: extern "C" fn(data: *const u8, data_len: size_t, argp: *mut c_void),
    argp: *mut c_void,
    level: *const c_char,
) {
    let argp = atomic::AtomicPtr::new(argp);
    let logger = Box::new(LogWriter { cb, argp });
    let _ = log::set_boxed_logger(logger);

    let level = unsafe { ffi::CStr::from_ptr(level).to_str().unwrap_or_default() };
    if let Ok(level_filter) = log::LevelFilter::from_str(level) {
        log::set_max_level(level_filter);
    }
}

#[repr(transparent)]
struct Context(*mut c_void);

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

/// Meta information of an incoming packet.
#[repr(C)]
pub struct PacketInfo<'a> {
    src: &'a sockaddr,
    src_len: socklen_t,
    dst: &'a sockaddr,
    dst_len: socklen_t,
}

impl From<&PacketInfo<'_>> for crate::PacketInfo {
    fn from(info: &PacketInfo) -> crate::PacketInfo {
        crate::PacketInfo {
            src: sock_addr_from_c(info.src, info.src_len),
            dst: sock_addr_from_c(info.dst, info.dst_len),
            time: std::time::Instant::now(),
        }
    }
}

/// Data and meta information of an outgoing packet.
#[repr(C)]
pub struct PacketOutSpec {
    iov: *const iovec,
    iovlen: size_t,
    src_addr: *const c_void,
    src_addr_len: socklen_t,
    dst_addr: *const c_void,
    dst_addr_len: socklen_t,
}

/// Path address representation for C API.
#[repr(C)]
pub struct PathAddress {
    local_addr: sockaddr_storage,
    local_addr_len: socklen_t,
    remote_addr: sockaddr_storage,
    remote_addr_len: socklen_t,
}

fn sock_addr_from_c(addr: &sockaddr, addr_len: socklen_t) -> SocketAddr {
    match addr.sa_family as i32 {
        AF_INET => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in>());
            let in4 = unsafe { *(addr as *const _ as *const sockaddr_in) };

            #[cfg(not(windows))]
            let addr = Ipv4Addr::from(u32::from_be(in4.sin_addr.s_addr));
            #[cfg(windows)]
            let addr = {
                let ip = unsafe { in4.sin_addr.S_un.S_un_b() };
                Ipv4Addr::from([ip.s_b1, ip.s_b2, ip.s_b3, ip.s_b4])
            };

            let port = u16::from_be(in4.sin_port);
            SocketAddrV4::new(addr, port).into()
        }
        AF_INET6 => {
            assert!(addr_len as usize == std::mem::size_of::<sockaddr_in6>());
            let in6 = unsafe { *(addr as *const _ as *const sockaddr_in6) };

            #[cfg(not(windows))]
            let addr = Ipv6Addr::from(in6.sin6_addr.s6_addr);
            #[cfg(windows)]
            let addr = Ipv6Addr::from(*unsafe { in6.sin6_addr.u.Byte() });

            let port = u16::from_be(in6.sin6_port);

            #[cfg(not(windows))]
            let scope_id = in6.sin6_scope_id;
            #[cfg(windows)]
            let scope_id = unsafe { *in6.u.sin6_scope_id() };

            SocketAddrV6::new(addr, port, in6.sin6_flowinfo, scope_id).into()
        }
        _ => unimplemented!("unsupported address type"),
    }
}

fn sock_addr_to_c(addr: &SocketAddr, out: &mut sockaddr_storage) -> socklen_t {
    let sin_port = addr.port().to_be();

    match addr {
        SocketAddr::V4(addr) => unsafe {
            let sa_len = std::mem::size_of::<sockaddr_in>();
            let out_in = out as *mut _ as *mut sockaddr_in;
            let s_addr = u32::from_ne_bytes(addr.ip().octets());

            #[cfg(not(windows))]
            let sin_addr = in_addr { s_addr };
            #[cfg(windows)]
            let sin_addr = {
                let mut s_un = std::mem::zeroed::<in_addr_S_un>();
                *s_un.S_addr_mut() = s_addr;
                in_addr { S_un: s_un }
            };

            *out_in = sockaddr_in {
                sin_family: AF_INET as sa_family_t,
                sin_addr,
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin_len: sa_len as u8,
                sin_port,
                sin_zero: std::mem::zeroed(),
            };
            sa_len as socklen_t
        },

        SocketAddr::V6(addr) => unsafe {
            let sa_len = std::mem::size_of::<sockaddr_in6>();
            let out_in6 = out as *mut _ as *mut sockaddr_in6;

            #[cfg(not(windows))]
            let sin6_addr = in6_addr {
                s6_addr: addr.ip().octets(),
            };
            #[cfg(windows)]
            let sin6_addr = {
                let mut u = std::mem::zeroed::<in6_addr_u>();
                *u.Byte_mut() = addr.ip().octets();
                in6_addr { u }
            };

            #[cfg(windows)]
            let u = {
                let mut u = std::mem::zeroed::<SOCKADDR_IN6_LH_u>();
                *u.sin6_scope_id_mut() = addr.scope_id();
                u
            };

            *out_in6 = sockaddr_in6 {
                sin6_family: AF_INET6 as sa_family_t,
                sin6_addr,
                #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
                sin6_len: sa_len as u8,
                sin6_port: sin_port,
                sin6_flowinfo: addr.flowinfo(),

                #[cfg(not(windows))]
                sin6_scope_id: addr.scope_id(),
                #[cfg(windows)]
                u,
            };
            sa_len as socklen_t
        },
    }
}
