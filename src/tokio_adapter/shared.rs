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

//! Shared QUIC state for direct-call stream I/O (Quinn-style).
//!
//! The [`Endpoint`] is wrapped in `Arc<Mutex<>>` so both the driver task
//! and user-facing stream handles can access it. Stream read/write
//! calls go directly through the Mutex instead of channel round-trips.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Waker;

use crate::Endpoint;

/// Per-stream waker storage (s2n-quic pattern: waker on struct).
#[derive(Default)]
pub(crate) struct StreamWakers {
    /// Waker registered when a write is blocked by flow control.
    pub write_waker: Option<Waker>,
    /// Waker registered when a read finds no available data.
    pub read_waker: Option<Waker>,
}

/// Shared QUIC state protected by Mutex.
///
/// Both the driver task and stream handles access this through
/// `Arc<Mutex<SharedInner>>`. The Mutex is [`std::sync::Mutex`]
/// (not tokio) because it is never held across `.await` points.
pub(crate) struct SharedInner {
    /// The tquic endpoint. `Send` via `unsafe impl` in tquic.
    pub endpoint: Endpoint,

    /// Per-stream wakers indexed by `(conn_index, stream_id)`.
    pub stream_wakers: HashMap<(u64, u64), StreamWakers>,
}

/// Alias for the shared state type.
pub(crate) type SharedState = Arc<Mutex<SharedInner>>;

impl SharedInner {
    /// Create a new shared state wrapping an endpoint.
    pub fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            stream_wakers: HashMap::new(),
        }
    }

    /// Register a waker to be called when the stream becomes writable.
    pub fn register_write_waker(&mut self, conn_idx: u64, stream_id: u64, waker: Waker) {
        self.stream_wakers
            .entry((conn_idx, stream_id))
            .or_default()
            .write_waker = Some(waker);
    }

    /// Register a waker to be called when the stream becomes readable.
    pub fn register_read_waker(&mut self, conn_idx: u64, stream_id: u64, waker: Waker) {
        self.stream_wakers
            .entry((conn_idx, stream_id))
            .or_default()
            .read_waker = Some(waker);
    }

    /// Take the write waker for a stream (if registered).
    pub fn take_write_waker(&mut self, conn_idx: u64, stream_id: u64) -> Option<Waker> {
        self.stream_wakers
            .get_mut(&(conn_idx, stream_id))?
            .write_waker
            .take()
    }

    /// Take the read waker for a stream (if registered).
    pub fn take_read_waker(&mut self, conn_idx: u64, stream_id: u64) -> Option<Waker> {
        self.stream_wakers
            .get_mut(&(conn_idx, stream_id))?
            .read_waker
            .take()
    }

    /// Remove all wakers for a connection (on close).
    ///
    /// Returns collected wakers so the caller can wake them
    /// outside the lock to avoid deadlocks.
    pub fn remove_conn_wakers(&mut self, conn_idx: u64) -> Vec<Waker> {
        let mut wakers = Vec::new();
        self.stream_wakers.retain(|&(ci, _), sw| {
            if ci == conn_idx {
                if let Some(w) = sw.write_waker.take() {
                    wakers.push(w);
                }
                if let Some(w) = sw.read_waker.take() {
                    wakers.push(w);
                }
                false
            } else {
                true
            }
        });
        wakers
    }

    /// Remove wakers for a specific stream.
    pub fn remove_stream_wakers(&mut self, conn_idx: u64, stream_id: u64) {
        self.stream_wakers.remove(&(conn_idx, stream_id));
    }
}
