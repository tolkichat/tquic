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
use std::sync::Arc;

use libc::c_char;
use libc::c_int;
use libc::c_void;
use libc::size_t;

use crate::tls::SslCtx;
use crate::tls::TlsConfig;

use super::CertCompressionAlgorithm;

/// Create a new TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new() -> *mut TlsConfig {
    match TlsConfig::new() {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new TlsConfig with SSL_CTX.
/// When using raw SSL_CTX, TlsSession::session() and TlsSession::set_keylog() won't take effect.
/// The caller is responsible for the memory of TlsConfig and SSL_CTX when use this function.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_with_ssl_ctx(ssl_ctx: *mut SslCtx) -> *mut TlsConfig {
    Box::into_raw(Box::new(TlsConfig::new_with_ssl_ctx(ssl_ctx)))
}

fn convert_application_protos(protos: *const *const c_char, proto_num: isize) -> Vec<Vec<u8>> {
    let mut application_protos = vec![];
    for i in 0..proto_num {
        let proto = unsafe { (*protos).offset(i) };
        if proto.is_null() {
            continue;
        }

        let proto = unsafe { ffi::CStr::from_ptr(proto).to_bytes().to_vec() };
        application_protos.push(proto);
    }

    application_protos
}

/// Create a new client side TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
/// For more information about `protos`, please see `quic_tls_config_set_application_protos`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_client_config(
    protos: *const *const c_char,
    proto_num: isize,
    enable_early_data: bool,
) -> *mut TlsConfig {
    if protos.is_null() {
        return ptr::null_mut();
    }

    let application_protos = convert_application_protos(protos, proto_num);
    match TlsConfig::new_client_config(application_protos, enable_early_data) {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Create a new server side TlsConfig.
/// The caller is responsible for the memory of the TlsConfig and should properly
/// destroy it by calling `quic_tls_config_free`.
/// For more information about `protos`, please see `quic_tls_config_set_application_protos`.
#[no_mangle]
pub extern "C" fn quic_tls_config_new_server_config(
    cert_file: *const c_char,
    key_file: *const c_char,
    protos: *const *const c_char,
    proto_num: isize,
    enable_early_data: bool,
) -> *mut TlsConfig {
    if cert_file.is_null() || key_file.is_null() || protos.is_null() {
        return ptr::null_mut();
    }

    let application_protos = convert_application_protos(protos, proto_num);
    let cert_file = unsafe {
        match ffi::CStr::from_ptr(cert_file).to_str() {
            Ok(cert_file) => cert_file,
            Err(_) => return ptr::null_mut(),
        }
    };
    let key_file = unsafe {
        match ffi::CStr::from_ptr(key_file).to_str() {
            Ok(key_file) => key_file,
            Err(_) => return ptr::null_mut(),
        }
    };
    match TlsConfig::new_server_config(cert_file, key_file, application_protos, enable_early_data) {
        Ok(tls_config) => Box::into_raw(Box::new(tls_config)),
        Err(_) => ptr::null_mut(),
    }
}

/// Destroy a TlsConfig instance.
#[no_mangle]
pub extern "C" fn quic_tls_config_free(tls_config: *mut TlsConfig) {
    unsafe {
        let _ = Box::from_raw(tls_config);
    };
}

/// Set whether early data is allowed.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_early_data_enabled(tls_config: &mut TlsConfig, enable: bool) {
    tls_config.set_early_data_enabled(enable)
}

/// Set the session lifetime in seconds
#[no_mangle]
pub extern "C" fn quic_tls_config_set_session_timeout(tls_config: &mut TlsConfig, timeout: u32) {
    tls_config.set_session_timeout(timeout)
}

/// Set the list of supported application protocols.
/// The `protos` is a pointer that points to an array, where each element of the array is a string
/// pointer representing an application protocol identifier. For example, you can define it as
/// follows: const char* const protos[2] = {"h3", "http/0.9"}.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_application_protos(
    tls_config: &mut TlsConfig,
    protos: *const *const c_char,
    proto_num: isize,
) -> c_int {
    if protos.is_null() {
        return -1;
    }

    let application_protos = convert_application_protos(protos, proto_num);
    match tls_config.set_application_protos(application_protos) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set session ticket key for server.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_ticket_key(
    tls_config: &mut TlsConfig,
    ticket_key: *const u8,
    ticket_key_len: size_t,
) -> c_int {
    let ticket_key = unsafe { slice::from_raw_parts(ticket_key, ticket_key_len) };
    match tls_config.set_ticket_key(ticket_key) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the certificate verification behavior.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_verify(tls_config: &mut TlsConfig, verify: bool) {
    tls_config.set_verify(verify)
}

/// Set the PEM-encoded certificate file.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_certificate_file(
    tls_config: &mut TlsConfig,
    cert_file: *const c_char,
) -> c_int {
    if cert_file.is_null() {
        return -1;
    }

    let cert_file = unsafe {
        match ffi::CStr::from_ptr(cert_file).to_str() {
            Ok(cert_file) => cert_file,
            Err(_) => return -1,
        }
    };
    match tls_config.set_certificate_file(cert_file) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set the PEM-encoded private key file.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_private_key_file(
    tls_config: &mut TlsConfig,
    key_file: *const c_char,
) -> c_int {
    if key_file.is_null() {
        return -1;
    }

    let key_file = unsafe {
        match ffi::CStr::from_ptr(key_file).to_str() {
            Ok(key_file) => key_file,
            Err(_) => return -1,
        }
    };
    match tls_config.set_private_key_file(key_file) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Set CA certificates.
#[no_mangle]
pub extern "C" fn quic_tls_config_set_ca_certs(
    tls_config: &mut TlsConfig,
    ca_path: *const c_char,
) -> c_int {
    if ca_path.is_null() {
        return -1;
    }

    let ca_path = unsafe {
        match ffi::CStr::from_ptr(ca_path).to_str() {
            Ok(ca_path) => ca_path,
            Err(_) => return -1,
        }
    };
    match tls_config.set_ca_certs(ca_path) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

/// Enable certificate compression for one or more algorithms.
/// Supported algorithms: Zlib(1), Brotli(2), Zstd(3).
/// The algorithms parameter is an array of algorithm values, and algorithms_len is the array length.
#[no_mangle]
pub extern "C" fn quic_tls_config_enable_certificate_compression(
    tls_config: &mut TlsConfig,
    algorithms: *const CertCompressionAlgorithm,
    algorithms_len: size_t,
) -> c_int {
    if algorithms.is_null() || algorithms_len == 0 {
        return -1;
    }

    let algorithms_slice = unsafe { slice::from_raw_parts(algorithms, algorithms_len) };
    let mut compression_algorithms = Vec::new();

    for &alg in algorithms_slice {
        let internal_alg = match alg {
            CertCompressionAlgorithm::Zlib => crate::tls::CertCompressionAlgorithm::Zlib,
            CertCompressionAlgorithm::Brotli => crate::tls::CertCompressionAlgorithm::Brotli,
            CertCompressionAlgorithm::Zstd => crate::tls::CertCompressionAlgorithm::Zstd,
        };
        compression_algorithms.push(internal_alg);
    }

    match tls_config.enable_certificate_compression(compression_algorithms) {
        Ok(_) => 0,
        Err(e) => e.to_errno() as c_int,
    }
}

// --- TlsConfigSelector handler types ---

#[repr(transparent)]
pub struct TlsConfigSelectorContext(pub(crate) *mut c_void);

#[repr(C)]
pub struct TlsConfigSelectMethods {
    pub get_default: fn(ctx: *mut c_void) -> *mut TlsConfig,
    pub select:
        fn(ctx: *mut c_void, server_name: *const u8, server_name_len: size_t) -> *mut TlsConfig,
}

#[repr(C)]
pub struct TlsConfigSelector {
    pub methods: *const TlsConfigSelectMethods,
    pub context: TlsConfigSelectorContext,
}

unsafe impl Send for TlsConfigSelector {}
unsafe impl Sync for TlsConfigSelector {}

impl crate::tls::TlsConfigSelector for TlsConfigSelector {
    fn get_default(&self) -> Option<Arc<TlsConfig>> {
        let tls_config = unsafe { ((*self.methods).get_default)(self.context.0) };
        if tls_config.is_null() {
            return None;
        }

        let tls_config = unsafe { tls_config.as_mut().unwrap() };
        let tls_config = Arc::new(TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx()));
        Some(tls_config)
    }

    fn select(&self, server_name: &str) -> Option<Arc<TlsConfig>> {
        let tls_config = unsafe {
            ((*self.methods).select)(
                self.context.0,
                server_name.as_ptr(),
                server_name.len() as size_t,
            )
        };
        if tls_config.is_null() {
            return None;
        }

        let tls_config = unsafe { tls_config.as_mut().unwrap() };
        let tls_config = Arc::new(TlsConfig::new_with_ssl_ctx(tls_config.ssl_ctx()));
        Some(tls_config)
    }
}
