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

//! Tokio async adapter for tquic.
//!
//! With `tokio-runtime` feature: mutex-based adapter (original).
//! With `tokio-reactor` feature: single-owner reactor (zero contention).

// --- Original mutex-based adapter (available under tokio-runtime without tokio-reactor) ---
#[cfg(not(feature = "tokio-reactor"))]
mod connection;
#[cfg(not(feature = "tokio-reactor"))]
mod endpoint;
mod error;
#[cfg(not(feature = "tokio-reactor"))]
mod stream;

#[cfg(not(feature = "tokio-reactor"))]
pub use connection::TquicConnection;
#[cfg(not(feature = "tokio-reactor"))]
pub use endpoint::TquicEndpoint;
pub use error::AsyncError;
#[cfg(not(feature = "tokio-reactor"))]
pub use stream::{RecvStream, SendStream};

// --- Single-owner reactor adapter ---
#[cfg(feature = "tokio-reactor")]
mod cmd;
#[cfg(feature = "tokio-reactor")]
mod reactor;
#[cfg(feature = "tokio-reactor")]
mod reactor_connection;
#[cfg(feature = "tokio-reactor")]
mod reactor_endpoint;
#[cfg(feature = "tokio-reactor")]
mod reactor_handler;
#[cfg(feature = "tokio-reactor")]
mod reactor_stream;

#[cfg(feature = "tokio-reactor")]
pub use reactor_connection::TquicConnection;
#[cfg(feature = "tokio-reactor")]
pub use reactor_endpoint::TquicEndpoint;
#[cfg(feature = "tokio-reactor")]
pub use reactor_stream::{RecvStream, SendStream};
