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

use std::any::Any;

use enumflags2::bitflags;
use enumflags2::BitFlags;
use smallvec::SmallVec;

use self::StreamFlags::*;
use super::recv_buf::RecvBuf;
use super::send_buf::SendBuf;
use super::StreamIdHashSet;
use crate::Error;
use crate::Result;

/// Various flags of QUIC stream
#[bitflags]
#[repr(u32)]
#[derive(Clone, Copy)]
enum StreamFlags {
    /// Upper layer want to read data from stream.
    WantRead = 1 << 0,

    /// Upper layer want to write data to stream.
    WantWrite = 1 << 1,

    /// The stream has been closed and is waiting to release its resources.
    Closed = 1 << 2,
}

#[derive(Default)]
pub struct Stream {
    /// Whether the stream is bidirectional.
    pub bidi: bool,

    /// Whether the stream was created by the local endpoint.
    pub local: bool,

    /// The stream's urgency.
    //  1. RFC 9000 - 5.3.  Stream Prioritization
    //    Stream multiplexing can have a significant effect on application performance
    //  if resources allocated to streams are correctly prioritized.
    //    QUIC does not provide a mechanism for exchanging prioritization information.
    //  Instead, it relies on receiving priority information from the application.
    //    A QUIC implementation SHOULD provide ways in which an application can indicate
    //  the relative priority of streams. An implementation uses information provided
    //  by the application to determine how to allocate resources to active streams.
    //
    //  2. RFC 9218 - 4.1. Urgency
    //    Endpoints use this parameter to communicate their view of the precedence of
    //  HTTP responses. The chosen value of urgency can be based on the expectation
    //  that servers might use this information to transmit HTTP responses in the order
    //  of their urgency. The smaller the value, the higher the precedence.
    pub urgency: u8,

    /// Whether the stream data can be send incrementally.
    //  1. RFC 9000 QUIC transport prototocl doesn't define incremental parameter.
    //  2. RFC 9218 - 4.2. Incremental
    //    The incremental parameter value is Boolean. It indicates if an HTTP response
    //  can be processed incrementally, i.e., provide some meaningful output as chunks
    //  of the response arrive.
    pub incremental: bool,

    /// Receive-side stream buffer.
    pub recv: RecvBuf,

    /// Send-side stream buffer.
    pub send: SendBuf,

    /// Application can write data to send buffer only when flow control capacity
    /// larger than this value.
    //  Use case: Headers need to be sent atomically, so we should make sure there
    //  has enough capacity before sending headers.
    pub write_thresh: usize,

    /// Various stream states.
    flags: BitFlags<StreamFlags>,

    /// For holding Application context.
    pub context: Option<Box<dyn Any + Send + Sync>>,

    /// Unique trace id for debug logging.
    pub(super) trace_id: String,
}

impl Stream {
    /// Create a new stream with the given flow control limits.
    pub fn new(
        bidi: bool,
        local: bool,
        max_tx_data: u64,
        max_rx_data: u64,
        max_window: u64,
    ) -> Stream {
        let flags = match bidi {
            // New bidi stream is always want to read and write.
            true => WantRead | WantWrite,
            false => {
                match local {
                    // New local initialize uni stream is always want to write, and not want to read.
                    true => WantWrite.into(),
                    // New remote initialize uni stream is always want to read, and not want to write.
                    false => WantRead.into(),
                }
            }
        };

        Stream {
            bidi,
            local,
            // 1.RFC9000 QUIC transport protocol doesn't specify the default value of
            // stream urgency.
            //
            // 2.RFC9218 define the HTTP stream urgency range from 0 to 7,
            // and 3 is the default, which is the middle of the range.
            //
            // 3.We use 127 as the default value, which is the middle of the u8 range.
            // not mandatory and can be changed, but we think 127 is a good choice.
            urgency: 127,
            // 1.RFC9000 QUIC transport protocol doesn't define incremental parameter.
            //
            // 2.RFC9218 define incremental parameter for HTTP, it indicates if HTTP
            // response can be processed incrementally, i.e, provide some meaningful
            // output as chunks of the response arrive.
            // The default value of incremental parameter is false(0).
            //
            // 3.Above all, we set the default value to true, which is more reasonable
            // and helps ensure fairness in scheduling.
            incremental: true,
            recv: RecvBuf::new(max_rx_data, max_window),
            send: SendBuf::new(max_tx_data),
            write_thresh: 1,
            flags,
            context: None,
            trace_id: String::new(),
        }
    }

    /// Set trace id.
    pub fn set_trace_id(&mut self, trace_id: &str) {
        self.trace_id = trace_id.to_string();
        self.send.trace_id = trace_id.to_string();
        self.recv.trace_id = trace_id.to_string();
    }

    /// Return true if the stream has data to be read or an error to be collected.
    pub fn is_readable(&self) -> bool {
        self.recv.ready()
    }

    /// Return true if the stream's send-side has not been shutdown by application
    /// and is not finished and it has enough flow control capacity to be written to.
    pub fn is_writable(&self) -> bool {
        !self.send.is_fin()
            && !self.send.is_shutdown()
            && (self.send.write_off + self.write_thresh as u64) <= self.send.max_data
    }

    /// Return true if the stream buffering some data and flow control allows some of
    /// them to be sent.
    pub fn is_sendable(&self) -> bool {
        self.send.ready()
    }

    /// Return true if the stream is complete.
    pub fn is_complete(&self) -> bool {
        match (self.bidi, self.local) {
            // For bidi streams, the stream is closed when both send and receive are
            // complete.
            (true, _) => self.send.is_complete() && self.recv.is_complete(),
            // For uni streams initialized locally, the stream is closed when the send
            // side is complete.
            (false, true) => self.send.is_complete(),
            // For uni streams initialized by peer, the stream is closed when the recv
            // side is complete.
            (false, false) => self.recv.is_complete(),
        }
    }

    /// Return true if the stream receive-side has been shutdown.
    /// If true, all new incoming data will be discarded.
    pub fn is_draining(&self) -> bool {
        self.recv.is_shutdown()
    }

    /// Check whether the stream is WantWrite
    pub fn is_wantwrite(&self) -> bool {
        self.flags.contains(WantWrite)
    }

    /// Mark the stream as WantWrite or not.
    ///
    /// Return error if the stream is not bidi and not local uni stream.
    pub fn mark_wantwrite(&mut self, flag: bool) -> Result<()> {
        if !self.bidi && !self.local {
            return Err(Error::InternalError);
        }

        match flag {
            true => self.flags.insert(WantWrite),
            false => self.flags.remove(WantWrite),
        };

        Ok(())
    }

    /// Check whether the stream is WantRead
    pub fn is_wantread(&self) -> bool {
        self.flags.contains(WantRead)
    }

    /// Mark the stream as WantRead.
    ///
    /// Return error if the stream is not bidi and not remote uni stream.
    pub fn mark_wantread(&mut self, flag: bool) -> Result<()> {
        if !self.bidi && self.local {
            return Err(Error::InternalError);
        }

        match flag {
            true => self.flags.insert(WantRead),
            false => self.flags.remove(WantRead),
        };

        Ok(())
    }

    /// Check whether the stream is closed.
    pub fn is_closed(&self) -> bool {
        self.flags.contains(Closed)
    }

    /// Mark the stream as closed.
    pub fn mark_closed(&mut self) {
        self.flags.insert(Closed);
    }
}

/// Return true if the stream was created locally.
///
/// The least significant bit (0x01) of the stream ID identifies the initiator
/// of the stream.
/// Client-initiated streams have even-numbered stream IDs (with the bit set to 0),
/// and server-initiated streams have odd-numbered stream IDs (with the bit set to 1).
pub(crate) fn is_local(stream_id: u64, is_server: bool) -> bool {
    (stream_id & 0x1) == (is_server as u64)
}

/// Return true if the stream is bidirectional.
///
/// The second least significant bit (0x02) of the stream ID distinguishes
/// between bidirectional streams (with the bit set to 0) and unidirectional
/// streams (with the bit set to 1).
pub fn is_bidi(stream_id: u64) -> bool {
    (stream_id & 0x2) == 0
}

/// An iterator over QUIC streams.
#[derive(Default)]
pub struct StreamIter {
    pub(super) streams: SmallVec<[u64; 8]>,
}

impl StreamIter {
    #[inline]
    pub(super) fn from(streams: &StreamIdHashSet) -> Self {
        StreamIter {
            streams: streams.iter().copied().collect(),
        }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        self.streams.pop()
    }
}

impl ExactSizeIterator for StreamIter {
    #[inline]
    fn len(&self) -> usize {
        self.streams.len()
    }
}
