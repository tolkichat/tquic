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

//! Stream types for the reactor pattern.
//!
//! [`SendStream`] and [`RecvStream`] communicate with the reactor
//! task via the data-plane channel. No mutexes are needed.

use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

use super::cmd::{DataCmd, ReadResult};
use super::error::AsyncError;
use crate::Shutdown;

/// Async send half of a QUIC stream (reactor version).
///
/// Sends write commands to the reactor via the data-plane channel.
pub struct SendStream {
    /// The QUIC stream ID.
    stream_id: u64,

    /// The parent connection index.
    conn_index: u64,

    /// Sender for data-plane commands.
    data_tx: mpsc::Sender<DataCmd>,

    /// Set to true after `finish()` is called, suppressing RESET on drop.
    finished: AtomicBool,
}

impl SendStream {
    /// Create a new `SendStream`.
    pub(crate) fn new(stream_id: u64, conn_index: u64, data_tx: mpsc::Sender<DataCmd>) -> Self {
        Self {
            stream_id,
            conn_index,
            data_tx,
            finished: AtomicBool::new(false),
        }
    }

    /// Write data to the stream.
    ///
    /// Returns the number of bytes written. The caller should
    /// retry with remaining data if fewer bytes were written.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.data_tx
            .send(DataCmd::StreamWrite {
                conn_index: self.conn_index,
                stream_id: self.stream_id,
                data: Bytes::copy_from_slice(buf),
                fin: false,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        rx.await.map_err(|_| AsyncError::ReactorGone)?
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

    /// Signal that no more data will be written (FIN).
    pub async fn finish(&self) -> Result<(), AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.data_tx
            .send(DataCmd::StreamWrite {
                conn_index: self.conn_index,
                stream_id: self.stream_id,
                data: Bytes::new(),
                fin: true,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        // finish sends zero-length with FIN; treat Done as success.
        match rx.await.map_err(|_| AsyncError::ReactorGone)? {
            Ok(_) | Err(AsyncError::Tquic(crate::Error::Done)) => {}
            Err(e) => return Err(e),
        }
        self.finished.store(true, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
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

/// Async receive half of a QUIC stream (reactor version).
///
/// Sends read commands to the reactor via the data-plane channel.
pub struct RecvStream {
    /// The QUIC stream ID.
    stream_id: u64,

    /// The parent connection index.
    conn_index: u64,

    /// Sender for data-plane commands.
    data_tx: mpsc::Sender<DataCmd>,
}

impl RecvStream {
    /// Create a new `RecvStream`.
    pub(crate) fn new(stream_id: u64, conn_index: u64, data_tx: mpsc::Sender<DataCmd>) -> Self {
        Self {
            stream_id,
            conn_index,
            data_tx,
        }
    }

    /// Read data from the stream into the provided buffer.
    ///
    /// Returns `Ok(Some(n))` with bytes read, or `Ok(None)` if
    /// the stream has been fully received (FIN).
    pub async fn read(&self, buf: &mut [u8]) -> Result<Option<usize>, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.data_tx
            .send(DataCmd::StreamRead {
                conn_index: self.conn_index,
                stream_id: self.stream_id,
                buf_len: buf.len(),
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;
        let result = rx.await.map_err(|_| AsyncError::ReactorGone)??;
        if result.fin && result.data.is_empty() {
            return Ok(None);
        }
        let n = result.data.len().min(buf.len());
        buf[..n].copy_from_slice(&result.data[..n]);
        Ok(Some(n))
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let _ = self.data_tx.try_send(DataCmd::StreamShutdown {
            conn_index: self.conn_index,
            stream_id: self.stream_id,
            direction: Shutdown::Read,
            error_code: 0,
        });
    }
}
