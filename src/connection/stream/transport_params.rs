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

use crate::TransportParams;

/// Initial transport parameters for streams.
#[derive(Clone, Copy, Debug, PartialEq, Default)]
pub struct StreamTransportParams {
    pub(super) initial_max_data: u64,
    pub(super) initial_max_stream_data_bidi_local: u64,
    pub(super) initial_max_stream_data_bidi_remote: u64,
    pub(super) initial_max_stream_data_uni: u64,
    pub(super) initial_max_streams_bidi: u64,
    pub(super) initial_max_streams_uni: u64,
}

impl StreamTransportParams {
    pub fn from(tp: &TransportParams) -> Self {
        StreamTransportParams {
            initial_max_data: tp.initial_max_data,
            initial_max_stream_data_bidi_local: tp.initial_max_stream_data_bidi_local,
            initial_max_stream_data_bidi_remote: tp.initial_max_stream_data_bidi_remote,
            initial_max_stream_data_uni: tp.initial_max_stream_data_uni,
            initial_max_streams_bidi: tp.initial_max_streams_bidi,
            initial_max_streams_uni: tp.initial_max_streams_uni,
        }
    }
}
