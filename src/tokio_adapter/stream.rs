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

//! Async QUIC stream types.
//!
//! [`SendStream`] and [`RecvStream`] lock the endpoint state directly
//! and use `poll_fn` with wakers for flow-control back-pressure.

use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;

use bytes::Bytes;

use super::endpoint::{extract_driver_waker, ConnectionInner};
use super::error::AsyncError;
use crate::Error as TquicError;
use crate::Shutdown;

/// Async send half of a QUIC stream.
///
/// Locks the endpoint state to call `stream_write` on the underlying
/// tquic `Connection`. Uses wakers registered in [`ConnAsyncState`]
/// for flow-control back-pressure.
pub struct SendStream {
    stream_id: u64,
    conn_index: u64,
    conn_inner: Arc<ConnectionInner>,
    /// Set to true after `finish()` is called to suppress the
    /// `Shutdown::Write` on drop (which would send RESET_STREAM).
    finished: AtomicBool,
}

impl SendStream {
    /// Create a new `SendStream`.
    pub(crate) fn new(stream_id: u64, conn_index: u64, conn_inner: Arc<ConnectionInner>) -> Self {
        Self {
            stream_id,
            conn_index,
            conn_inner,
            finished: AtomicBool::new(false),
        }
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written. The caller should
    /// retry with remaining data if fewer bytes were written.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, AsyncError> {
        let data = Bytes::copy_from_slice(buf);
        let stream_id = self.stream_id;
        let conn_index = self.conn_index;
        let conn_inner = &self.conn_inner;

        poll_fn(|cx| {
            // Check if connection is closed.
            if conn_inner
                .conn_state
                .lock()
                .expect("conn_state lock")
                .close_info
                .is_some()
            {
                return Poll::Ready(Err(AsyncError::ConnectionClosed));
            }

            let mut state = conn_inner.endpoint.state.lock().expect("endpoint lock");
            let conn = match state.endpoint.conn_get_mut(conn_index) {
                Some(c) => c,
                None => return Poll::Ready(Err(AsyncError::ConnectionClosed)),
            };

            match conn.stream_write(stream_id, data.clone(), false) {
                Ok(n) => {
                    let waker = extract_driver_waker(&state);
                    drop(state);
                    if let Some(w) = waker {
                        w.wake();
                    }
                    Poll::Ready(Ok(n))
                }
                Err(TquicError::Done) => {
                    // Flow control blocked -- register waker.
                    conn_inner
                        .conn_state
                        .lock()
                        .expect("conn_state lock")
                        .write_wakers
                        .insert(stream_id, cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(AsyncError::Tquic(e))),
            }
        })
        .await
    }

    /// Write all data to the stream, retrying until complete.
    pub async fn write_all(&self, buf: &[u8]) -> Result<(), AsyncError> {
        let mut offset = 0;
        while offset < buf.len() {
            let n = self.write(&buf[offset..]).await?;
            offset += n;
        }
        Ok(())
    }

    /// Signal that no more data will be written to this stream.
    pub async fn finish(&self) -> Result<(), AsyncError> {
        let waker = {
            let mut state = self
                .conn_inner
                .endpoint
                .state
                .lock()
                .expect("endpoint lock");
            let conn = state
                .endpoint
                .conn_get_mut(self.conn_index)
                .ok_or(AsyncError::ConnectionClosed)?;

            // Send a zero-length write with FIN.
            match conn.stream_write(self.stream_id, Bytes::new(), true) {
                Ok(_) | Err(TquicError::Done) => {}
                Err(e) => return Err(AsyncError::Tquic(e)),
            }

            self.finished.store(true, Ordering::Relaxed);
            extract_driver_waker(&state)
        };
        // Wake driver outside the lock.
        if let Some(w) = waker {
            w.wake();
        }
        Ok(())
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        // Only send RESET_STREAM if finish() was never called.
        if !self.finished.load(Ordering::Relaxed) {
            if let Ok(mut state) = self.conn_inner.endpoint.state.lock() {
                if let Some(conn) = state.endpoint.conn_get_mut(self.conn_index) {
                    let _ = conn.stream_shutdown(self.stream_id, Shutdown::Write, 0);
                }
            }
        }
    }
}

/// Async receive half of a QUIC stream.
///
/// Locks the endpoint state to call `stream_read` on the underlying
/// tquic `Connection`. Uses wakers registered in [`ConnAsyncState`]
/// for notification when data arrives.
pub struct RecvStream {
    stream_id: u64,
    conn_index: u64,
    conn_inner: Arc<ConnectionInner>,
}

impl RecvStream {
    /// Create a new `RecvStream`.
    pub(crate) fn new(stream_id: u64, conn_index: u64, conn_inner: Arc<ConnectionInner>) -> Self {
        Self {
            stream_id,
            conn_index,
            conn_inner,
        }
    }

    /// Read data from the stream into the provided buffer.
    ///
    /// Returns `Ok(Some(n))` with bytes read, or `Ok(None)` if
    /// the stream has been fully received (FIN).
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>, AsyncError> {
        let stream_id = self.stream_id;
        let conn_index = self.conn_index;
        let conn_inner = &self.conn_inner;

        poll_fn(|cx| {
            // Check if connection is closed.
            if conn_inner
                .conn_state
                .lock()
                .expect("conn_state lock")
                .close_info
                .is_some()
            {
                return Poll::Ready(Ok(None));
            }

            let mut state = conn_inner.endpoint.state.lock().expect("endpoint lock");
            let conn = match state.endpoint.conn_get_mut(conn_index) {
                Some(c) => c,
                None => return Poll::Ready(Ok(None)),
            };

            match conn.stream_read(stream_id, buf) {
                Ok((0, true)) => Poll::Ready(Ok(None)),
                Ok((n, _fin)) => Poll::Ready(Ok(Some(n))),
                Err(TquicError::Done) => {
                    // Check if the stream is fully consumed (EOF).
                    if conn.stream_finished(stream_id) {
                        return Poll::Ready(Ok(None));
                    }
                    // No data available yet -- register waker.
                    conn_inner
                        .conn_state
                        .lock()
                        .expect("conn_state lock")
                        .read_wakers
                        .insert(stream_id, cx.waker().clone());
                    Poll::Pending
                }
                Err(TquicError::StreamStateError) => {
                    // Stream closed or never opened -- treat as EOF.
                    Poll::Ready(Ok(None))
                }
                Err(e) => Poll::Ready(Err(AsyncError::Tquic(e))),
            }
        })
        .await
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        if let Ok(mut state) = self.conn_inner.endpoint.state.lock() {
            if let Some(conn) = state.endpoint.conn_get_mut(self.conn_index) {
                let _ = conn.stream_shutdown(self.stream_id, Shutdown::Read, 0);
            }
        }
    }
}
