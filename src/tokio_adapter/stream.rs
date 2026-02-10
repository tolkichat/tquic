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
//! [`SendStream`] and [`RecvStream`] provide async write and read
//! halves of a QUIC stream, communicating with the driver via channels.

use std::sync::Arc;

use bytes::Bytes;
use tokio::sync::{mpsc, oneshot, Notify};

use super::error::AsyncError;
use crate::Error as TquicError;
use crate::Shutdown;

/// Commands sent from stream handles to the driver loop.
pub(crate) enum StreamCmd {
    /// Write data to a stream.
    Write {
        stream_id: u64,
        data: Bytes,
        fin: bool,
        result_tx: oneshot::Sender<Result<usize, TquicError>>,
    },
    /// Read data from a stream.
    Read {
        stream_id: u64,
        buf_size: usize,
        result_tx: oneshot::Sender<Result<(Vec<u8>, bool), TquicError>>,
    },
    /// Shutdown one direction of a stream.
    Shutdown {
        stream_id: u64,
        direction: Shutdown,
    },
}

/// Async send half of a QUIC stream.
pub struct SendStream {
    pub(crate) stream_id: u64,
    pub(crate) conn_index: u64,
    pub(crate) cmd_tx: mpsc::Sender<StreamCmd>,
    pub(crate) writable: Arc<Notify>,
}

impl SendStream {
    /// Write data to the stream.
    ///
    /// Returns the number of bytes written. The caller should
    /// retry with remaining data if fewer bytes were written.
    pub async fn write(&self, buf: &[u8]) -> Result<usize, AsyncError> {
        self.writable.notified().await;
        self.write_inner(buf, false).await
    }

    /// Write all data to the stream, retrying until complete.
    pub async fn write_all(&self, buf: &[u8]) -> Result<(), AsyncError> {
        let mut offset = 0;
        while offset < buf.len() {
            self.writable.notified().await;
            let n = self.write_inner(&buf[offset..], false).await?;
            offset += n;
        }
        Ok(())
    }

    /// Signal that no more data will be written to this stream.
    pub async fn finish(&self) -> Result<(), AsyncError> {
        self.write_inner(&[], true).await?;
        Ok(())
    }

    /// Send a write command to the driver and await the result.
    async fn write_inner(
        &self,
        buf: &[u8],
        fin: bool,
    ) -> Result<usize, AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        let cmd = StreamCmd::Write {
            stream_id: self.stream_id,
            data: Bytes::copy_from_slice(buf),
            fin,
            result_tx,
        };
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx
            .await
            .map_err(|_| AsyncError::ChannelClosed)?
            .map_err(AsyncError::Tquic)
    }
}

impl Drop for SendStream {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(StreamCmd::Shutdown {
            stream_id: self.stream_id,
            direction: Shutdown::Write,
        });
    }
}

/// Async receive half of a QUIC stream.
pub struct RecvStream {
    pub(crate) stream_id: u64,
    pub(crate) conn_index: u64,
    pub(crate) cmd_tx: mpsc::Sender<StreamCmd>,
    pub(crate) readable: Arc<Notify>,
}

impl RecvStream {
    /// Read data from the stream into the provided buffer.
    ///
    /// Returns `Ok(Some(n))` with bytes read, or `Ok(None)` if
    /// the stream has been fully received (FIN).
    pub async fn read(
        &self,
        buf: &mut [u8],
    ) -> Result<Option<usize>, AsyncError> {
        self.readable.notified().await;
        let (result_tx, result_rx) = oneshot::channel();
        let cmd = StreamCmd::Read {
            stream_id: self.stream_id,
            buf_size: buf.len(),
            result_tx,
        };
        self.cmd_tx
            .send(cmd)
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        let (data, fin) = result_rx
            .await
            .map_err(|_| AsyncError::ChannelClosed)?
            .map_err(AsyncError::Tquic)?;
        if data.is_empty() && fin {
            return Ok(None);
        }
        let n = data.len().min(buf.len());
        buf[..n].copy_from_slice(&data[..n]);
        Ok(Some(n))
    }
}

impl Drop for RecvStream {
    fn drop(&mut self) {
        let _ = self.cmd_tx.try_send(StreamCmd::Shutdown {
            stream_id: self.stream_id,
            direction: Shutdown::Read,
        });
    }
}
