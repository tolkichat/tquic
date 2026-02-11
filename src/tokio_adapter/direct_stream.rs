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

//! Direct-call stream types using shared Mutex (Quinn-style).
//!
//! [`SendStream`] and [`RecvStream`] lock the shared `Mutex<SharedInner>`
//! and call `stream_write`/`stream_read` directly on the tquic Connection.
//! This eliminates the 2 context switches per operation from the slot-based
//! approach, matching Quinn's zero-overhead data path.

use std::future::poll_fn;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::Poll;

use bytes::Bytes;
use tokio::sync::{mpsc, Notify};

use super::cmd::DataCmd;
use super::error::AsyncError;
use super::shared::SharedState;
use crate::Shutdown;

// ---------------------------------------------------------------------------
// SendStream
// ---------------------------------------------------------------------------

/// Async send half of a QUIC stream (direct Mutex, zero context-switch).
///
/// Writes lock the shared [`Mutex`] and call `stream_write` directly
/// on the tquic [`Connection`], then wake the driver to flush packets.
pub struct SendStream {
    /// The QUIC stream ID.
    stream_id: u64,

    /// The parent connection index.
    conn_index: u64,

    /// Shared endpoint state behind a Mutex.
    shared: SharedState,

    /// Wake the driver to call `process_connections` / send packets.
    driver_notify: Arc<Notify>,

    /// Data channel for shutdown commands (fire-and-forget on drop).
    data_tx: mpsc::Sender<DataCmd>,

    /// Suppresses `RESET_STREAM` on drop after [`finish`](Self::finish).
    finished: AtomicBool,
}

impl SendStream {
    /// Create a new direct-call `SendStream`.
    pub(crate) fn new(
        stream_id: u64,
        conn_index: u64,
        shared: SharedState,
        driver_notify: Arc<Notify>,
        data_tx: mpsc::Sender<DataCmd>,
    ) -> Self {
        Self {
            stream_id,
            conn_index,
            shared,
            driver_notify,
            data_tx,
            finished: AtomicBool::new(false),
        }
    }

    /// Write data to the stream (copies from slice).
    ///
    /// Returns the number of bytes written. The caller should retry
    /// with remaining data if fewer bytes were written.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] if the connection is closed or a stream
    /// error occurs.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, AsyncError> {
        self.write_bytes_inner(Bytes::copy_from_slice(buf), false)
            .await
    }

    /// Write all data to the stream (copies from slice).
    ///
    /// Loops internally until the entire buffer is consumed by
    /// the QUIC flow-control window.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] on the first stream or connection error.
    pub async fn write_all(&self, buf: &[u8]) -> Result<(), AsyncError> {
        self.write_all_inner(Bytes::copy_from_slice(buf), false)
            .await
    }

    /// Write data from a [`Bytes`] buffer (zero-copy partial write).
    ///
    /// Returns the number of bytes written. The caller should retry
    /// with remaining data if fewer bytes were written.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] if the connection is closed or a stream
    /// error occurs.
    pub async fn write_bytes(&self, data: Bytes) -> Result<usize, AsyncError> {
        self.write_bytes_inner(data, false).await
    }

    /// Write all data from a [`Bytes`] buffer (zero-copy).
    ///
    /// Loops internally until the entire buffer is consumed.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] on the first stream or connection error.
    pub async fn write_all_bytes(&self, data: Bytes) -> Result<(), AsyncError> {
        self.write_all_inner(data, false).await
    }

    /// Signal that no more data will be written (FIN).
    ///
    /// After this call, the drop guard will **not** send
    /// `RESET_STREAM` to the peer.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] if the connection is closed or a stream
    /// error occurs.
    pub async fn finish(&self) -> Result<(), AsyncError> {
        self.finish_inner(Bytes::new()).await
    }

    /// Send remaining data with FIN in a single operation (zero-copy).
    ///
    /// Combines a final data write and stream finish into one call.
    /// After this, the drop guard will **not** send `RESET_STREAM`.
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] if the connection is closed or a stream
    /// error occurs.
    pub async fn finish_with_data(&self, data: Bytes) -> Result<(), AsyncError> {
        self.finish_inner(data).await
    }

    // -- private helpers ----------------------------------------------------

    /// Core write: lock Mutex, call `stream_write`, wake driver on success.
    ///
    /// Returns `Poll::Pending` when flow-control blocks (`Error::Done`),
    /// registering the task's waker for later notification.
    async fn write_bytes_inner(&self, data: Bytes, fin: bool) -> Result<usize, AsyncError> {
        poll_fn(|cx| {
            let mut inner = self.shared.lock().expect("shared state poisoned");
            let conn = match inner.endpoint.conn_get_mut(self.conn_index) {
                Some(c) => c,
                None => return Poll::Ready(Err(AsyncError::ConnectionClosed)),
            };
            match conn.stream_write(self.stream_id, data.clone(), fin) {
                Ok(n) => {
                    drop(inner);
                    self.driver_notify.notify_one();
                    Poll::Ready(Ok(n))
                }
                Err(crate::Error::Done) => {
                    inner.register_write_waker(self.conn_index, self.stream_id, cx.waker().clone());
                    Poll::Pending
                }
                Err(e) => Poll::Ready(Err(AsyncError::Tquic(e))),
            }
        })
        .await
    }

    /// Batch write all data in a single lock cycle.
    ///
    /// Holds the lock and drains as much as flow control allows,
    /// notifying the driver only once after draining (not per chunk).
    async fn write_all_inner(&self, data: Bytes, fin: bool) -> Result<(), AsyncError> {
        if data.is_empty() && !fin {
            return Ok(());
        }
        let mut remaining = data;
        poll_fn(|cx| {
            let mut inner = self.shared.lock().expect("shared state poisoned");
            let conn = match inner.endpoint.conn_get_mut(self.conn_index) {
                Some(c) => c,
                None => return Poll::Ready(Err(AsyncError::ConnectionClosed)),
            };
            // Drain as much as flow control allows in one lock
            loop {
                match conn.stream_write(self.stream_id, remaining.clone(), fin) {
                    Ok(n) if n >= remaining.len() => {
                        // All data consumed
                        drop(inner);
                        self.driver_notify.notify_one();
                        return Poll::Ready(Ok(()));
                    }
                    Ok(n) => {
                        // Partial write — continue without releasing lock
                        remaining = remaining.slice(n..);
                    }
                    Err(crate::Error::Done) => {
                        // Flow control blocked — flush what we wrote so far
                        inner.register_write_waker(
                            self.conn_index,
                            self.stream_id,
                            cx.waker().clone(),
                        );
                        drop(inner);
                        self.driver_notify.notify_one();
                        return Poll::Pending;
                    }
                    Err(e) => return Poll::Ready(Err(AsyncError::Tquic(e))),
                }
            }
        })
        .await
    }

    /// Write data + FIN, marking stream as finished on success.
    async fn finish_inner(&self, data: Bytes) -> Result<(), AsyncError> {
        let result = self.write_all_inner(data, true).await;
        match result {
            Ok(()) | Err(AsyncError::Tquic(crate::Error::Done)) => {
                self.finished.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        // Clean up waker registration.
        if let Ok(mut inner) = self.shared.lock() {
            inner.remove_stream_wakers(self.conn_index, self.stream_id);
        }
        // Send RESET_STREAM if not finished.
        if !self.finished.load(Ordering::Relaxed) {
            let _ = self.data_tx.try_send(DataCmd::StreamShutdown {
                conn_index: self.conn_index,
                stream_id: self.stream_id,
                direction: Shutdown::Write,
                error_code: 0,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// RecvStream
// ---------------------------------------------------------------------------

/// Async receive half of a QUIC stream (direct Mutex, zero context-switch).
///
/// Reads lock the shared [`Mutex`] and call `stream_read` directly
/// on the tquic [`Connection`].
pub struct RecvStream {
    /// The QUIC stream ID.
    stream_id: u64,

    /// The parent connection index.
    conn_index: u64,

    /// Shared endpoint state behind a Mutex.
    shared: SharedState,

    /// Wake the driver after reads (flow-control credits may change).
    driver_notify: Arc<Notify>,

    /// Data channel for shutdown commands (fire-and-forget on drop).
    data_tx: mpsc::Sender<DataCmd>,
}

impl RecvStream {
    /// Create a new direct-call `RecvStream`.
    pub(crate) fn new(
        stream_id: u64,
        conn_index: u64,
        shared: SharedState,
        driver_notify: Arc<Notify>,
        data_tx: mpsc::Sender<DataCmd>,
    ) -> Self {
        Self {
            stream_id,
            conn_index,
            shared,
            driver_notify,
            data_tx,
        }
    }

    /// Read data from the stream into the provided buffer.
    ///
    /// Returns `Ok(Some(n))` with bytes read, or `Ok(None)` if the
    /// stream has been fully received (FIN).
    ///
    /// # Errors
    ///
    /// Returns [`AsyncError`] if the connection is closed or a stream
    /// error occurs.
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>, AsyncError> {
        poll_fn(|cx| self.poll_read(buf, cx)).await
    }

    /// Read available data, filling as much of the buffer as possible.
    ///
    /// Unlike [`read`], this method continues reading within a single
    /// lock cycle until the buffer is full, the stream is finished,
    /// or no more data is currently available. This reduces lock
    /// overhead for bulk transfers.
    ///
    /// Returns `Ok(Some(n))` with total bytes read, or `Ok(None)`
    /// if the stream has been fully received (FIN).
    pub async fn read_chunk(&self, buf: &mut [u8]) -> Result<Option<usize>, AsyncError> {
        poll_fn(|cx| self.poll_read_chunk(buf, cx)).await
    }

    // -- private helpers ----------------------------------------------------

    /// Core read poll: lock Mutex, call `stream_read`, handle results.
    fn poll_read(
        &self,
        buf: &mut [u8],
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<usize>, AsyncError>> {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let conn = match inner.endpoint.conn_get_mut(self.conn_index) {
            Some(c) => c,
            None => return Poll::Ready(Err(AsyncError::ConnectionClosed)),
        };
        match conn.stream_read(self.stream_id, buf) {
            Ok((0, true)) => Poll::Ready(Ok(None)),
            Ok((n, _fin)) => {
                drop(inner);
                self.driver_notify.notify_one();
                Poll::Ready(Ok(Some(n)))
            }
            Err(crate::Error::Done) => {
                if conn.stream_finished(self.stream_id) {
                    Poll::Ready(Ok(None))
                } else {
                    inner.register_read_waker(self.conn_index, self.stream_id, cx.waker().clone());
                    Poll::Pending
                }
            }
            Err(crate::Error::StreamStateError) => Poll::Ready(Ok(None)),
            Err(e) => Poll::Ready(Err(AsyncError::Tquic(e))),
        }
    }

    /// Batch read: lock once, drain all available data into buf.
    fn poll_read_chunk(
        &self,
        buf: &mut [u8],
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<Option<usize>, AsyncError>> {
        let mut inner = self.shared.lock().expect("shared state poisoned");
        let conn = match inner.endpoint.conn_get_mut(self.conn_index) {
            Some(c) => c,
            None => return Poll::Ready(Err(AsyncError::ConnectionClosed)),
        };
        let mut total = 0;
        loop {
            match conn.stream_read(self.stream_id, &mut buf[total..]) {
                Ok((0, true)) => {
                    if total > 0 {
                        drop(inner);
                        self.driver_notify.notify_one();
                        return Poll::Ready(Ok(Some(total)));
                    }
                    return Poll::Ready(Ok(None));
                }
                Ok((n, fin)) => {
                    total += n;
                    if fin || total >= buf.len() {
                        drop(inner);
                        self.driver_notify.notify_one();
                        if total == 0 && fin {
                            return Poll::Ready(Ok(None));
                        }
                        return Poll::Ready(Ok(Some(total)));
                    }
                    // Continue reading within same lock
                }
                Err(crate::Error::Done) => {
                    if total > 0 {
                        drop(inner);
                        self.driver_notify.notify_one();
                        return Poll::Ready(Ok(Some(total)));
                    }
                    if conn.stream_finished(self.stream_id) {
                        return Poll::Ready(Ok(None));
                    }
                    inner.register_read_waker(
                        self.conn_index,
                        self.stream_id,
                        cx.waker().clone(),
                    );
                    return Poll::Pending;
                }
                Err(crate::Error::StreamStateError) => {
                    if total > 0 {
                        drop(inner);
                        self.driver_notify.notify_one();
                        return Poll::Ready(Ok(Some(total)));
                    }
                    return Poll::Ready(Ok(None));
                }
                Err(e) => return Poll::Ready(Err(AsyncError::Tquic(e))),
            }
        }
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        // Clean up waker registration.
        if let Ok(mut inner) = self.shared.lock() {
            inner.remove_stream_wakers(self.conn_index, self.stream_id);
        }
        // Send STOP_SENDING to peer.
        let _ = self.data_tx.try_send(DataCmd::StreamShutdown {
            conn_index: self.conn_index,
            stream_id: self.stream_id,
            direction: Shutdown::Read,
            error_code: 0,
        });
    }
}
