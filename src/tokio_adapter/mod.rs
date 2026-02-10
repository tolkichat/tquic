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
//! to tokio's async runtime using channels and `LocalSet`.
//!
//! tquic's `Endpoint` and `Connection` use `Rc<RefCell<>>` internally,
//! making them `!Send`. This adapter confines all tquic objects to a
//! single-threaded `LocalSet` and exposes `Send`-safe handles via
//! tokio channels.

mod connection;
mod driver;
mod endpoint;
mod error;
mod stream;

pub use connection::TquicConnection;
pub use endpoint::TquicEndpoint;
pub use error::AsyncError;
pub use stream::{RecvStream, SendStream};
