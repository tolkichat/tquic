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

use std::time::Instant;

use bytes::Buf;
use bytes::Bytes;

/// Range buffer containing data at a specific offset.
///
/// The data is stored in a `Bytes` in a manner that allows for sharing
/// among multiple instances of `RangeBuf`.
#[derive(Clone, Debug)]
pub struct RangeBuf {
    /// The buffer that stores the data.
    pub(super) data: Bytes,

    /// The starting offset of current buffer in a stream.
    pub(super) off: u64,

    /// Whether current buffer holds the stream's final offset.
    pub(super) fin: bool,

    // The moment when the data arrives.
    pub time: Instant,
}

impl RangeBuf {
    /// Create a new `RangeBuf` with the given Bytes.
    pub(super) fn new(buf: Bytes, off: u64, fin: bool) -> RangeBuf {
        RangeBuf {
            data: buf,
            off,
            fin,
            time: Instant::now(),
        }
    }

    /// Return true if current buffer holds the stream's final offset.
    pub(super) fn fin(&self) -> bool {
        self.fin
    }

    /// Get the starting offset of current buffer in a stream.
    pub(super) fn off(&self) -> u64 {
        self.off
    }

    /// Get the largest offset of current buffer in a stream.
    pub(super) fn max_off(&self) -> u64 {
        self.off() + self.len() as u64
    }

    /// Get the length of current buffer.
    pub(super) fn len(&self) -> usize {
        self.data.len()
    }

    /// Return true if current buffer's length is zero.
    pub(super) fn is_empty(&self) -> bool {
        self.data.len() == 0
    }

    /// Consume the starting `count` bytes of current buffer.
    /// This is equivalent to `self.advance(count)`.
    pub(super) fn consume(&mut self, count: usize) {
        self.data.advance(count);
        self.off += count as u64;
    }

    /// Advance the internal cursor of current buffer.
    pub(super) fn advance(&mut self, count: usize) {
        self.data.advance(count);
        self.off += count as u64;
    }

    /// Split the buffer into two at the given index.
    /// Afterwards self.data contains elements [0, at),
    /// and the returned RangeBuf.data contains elements [at, len).
    pub(super) fn split_off(&mut self, at: usize) -> RangeBuf {
        let buf = RangeBuf {
            data: self.data.split_off(at),
            off: self.off + at as u64,
            fin: self.fin,
            time: self.time,
        };

        self.fin = false;

        buf
    }

    /// Split the buffer into two at the given index.
    /// Afterwards self.data contains elements [at, len),
    /// and the returned RangeBuf.data contains elements [0, at).
    pub(super) fn split_to(&mut self, at: usize) -> RangeBuf {
        let buf = RangeBuf {
            data: self.data.split_to(at),
            off: self.off,
            fin: false,
            time: self.time,
        };

        self.off += at as u64;

        buf
    }
}

impl std::ops::Deref for RangeBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.data.deref()
    }
}
