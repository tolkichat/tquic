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

//! Error types for the tokio async adapter.

use std::fmt;

use crate::Error as TquicError;

/// Errors returned by async adapter operations.
#[derive(Debug)]
pub enum AsyncError {
    /// An error from the underlying tquic library.
    Tquic(TquicError),

    /// The connection has been closed.
    ConnectionClosed,

    /// An internal channel was closed unexpectedly.
    ChannelClosed,

    /// The operation timed out.
    Timeout,

    /// The reactor task has exited.
    ReactorGone,
}

impl fmt::Display for AsyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AsyncError::Tquic(e) => write!(f, "tquic error: {e}"),
            AsyncError::ConnectionClosed => write!(f, "connection closed"),
            AsyncError::ChannelClosed => write!(f, "channel closed"),
            AsyncError::Timeout => write!(f, "timeout"),
            AsyncError::ReactorGone => write!(f, "reactor task gone"),
        }
    }
}

impl std::error::Error for AsyncError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AsyncError::Tquic(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TquicError> for AsyncError {
    fn from(err: TquicError) -> Self {
        AsyncError::Tquic(err)
    }
}
