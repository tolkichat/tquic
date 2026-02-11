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
//! Provides async/await API bridging tquic's callback-based model
//! to tokio's async runtime using `Arc<Mutex>` and poll-based Futures.
//!
//! With the `tokio-runtime` feature, tquic's `Endpoint` and `Connection`
//! are `Send + Sync` (using `Arc`/`Mutex` internally). This adapter
//! wraps them behind `Arc<Mutex<EndpointState>>` and spawns an
//! `EndpointDriver` Future on a regular tokio task (no `LocalSet`
//! or dedicated OS thread needed).

mod connection;
mod endpoint;
mod error;
mod stream;

pub use connection::TquicConnection;
pub use endpoint::TquicEndpoint;
pub use error::AsyncError;
pub use stream::{RecvStream, SendStream};
