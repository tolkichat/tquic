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

//! Driver event loop for the tokio async adapter.
//!
//! The driver runs on a `tokio::task::LocalSet` because tquic's
//! `Endpoint` and `Connection` are `!Send`. It bridges tquic's
//! callback-based `TransportHandler` to async channels.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::{mpsc, watch, Notify};

use super::connection::{ConnCmd, ConnectionCloseInfo, TquicConnection};
use super::endpoint::{EndpointCmd, TquicEndpoint};
use super::error::AsyncError;
use super::stream::{RecvStream, SendStream, StreamCmd};

/// Per-connection state tracked by the driver.
#[allow(dead_code)]
struct ConnectionState {
    /// Notified when the handshake completes.
    established: Arc<Notify>,

    /// Sender for connection close information.
    close_tx: watch::Sender<Option<ConnectionCloseInfo>>,

    /// Receiver for stream-level commands from stream handles.
    stream_cmd_rx: mpsc::Receiver<StreamCmd>,

    /// Receiver for connection-level commands from the handle.
    conn_cmd_rx: mpsc::Receiver<ConnCmd>,

    /// Per-stream readable notifications.
    stream_readables: HashMap<u64, Arc<Notify>>,

    /// Per-stream writable notifications.
    stream_writables: HashMap<u64, Arc<Notify>>,

    /// Sender for incoming bidirectional streams.
    incoming_bi_tx: mpsc::Sender<(SendStream, RecvStream)>,

    /// Sender for incoming unidirectional streams.
    incoming_uni_tx: mpsc::Sender<RecvStream>,

    /// Sender for stream commands (cloned into new stream handles).
    stream_cmd_tx: mpsc::Sender<StreamCmd>,
}

/// Spawn the driver event loop and return a `Send`-safe endpoint handle.
///
/// The driver runs on a `LocalSet` in a dedicated thread because tquic
/// types are `!Send`. The returned `TquicEndpoint` communicates with
/// the driver via channels.
pub(crate) async fn spawn_driver(
    bind: SocketAddr,
    _config: crate::Config,
    _is_server: bool,
) -> Result<TquicEndpoint, AsyncError> {
    let socket = std::net::UdpSocket::bind(bind)
        .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;
    let local_addr = socket
        .local_addr()
        .map_err(|e| AsyncError::Tquic(crate::Error::from(e)))?;

    let (endpoint_cmd_tx, _endpoint_cmd_rx) =
        mpsc::channel::<EndpointCmd>(64);
    let (_incoming_tx, incoming_rx) =
        mpsc::channel::<TquicConnection>(64);

    // TODO: Spawn a dedicated thread with a LocalSet that runs the
    // driver event loop. The loop will:
    //   1. Create the tquic Endpoint inside the LocalSet (it is !Send)
    //   2. Receive UDP packets from the socket
    //   3. Feed packets into the Endpoint
    //   4. Process EndpointCmd / ConnCmd / StreamCmd from channels
    //   5. Send outgoing UDP packets
    //   6. Handle timer expiration via tokio::time::sleep

    Ok(TquicEndpoint::new(endpoint_cmd_tx, incoming_rx, local_addr))
}
