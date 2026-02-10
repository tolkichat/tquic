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

//! Async QUIC endpoint.
//!
//! [`TquicEndpoint`] provides a `Send`-safe async API for creating
//! QUIC client and server endpoints. The actual tquic `Endpoint` runs
//! on a `LocalSet`; this handle communicates with it via channels.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};

use super::connection::TquicConnection;
use super::error::AsyncError;

/// Commands sent from the endpoint handle to the driver.
pub(crate) enum EndpointCmd {
    /// Initiate a new outgoing connection.
    Connect {
        remote: SocketAddr,
        server_name: String,
        session: Option<Vec<u8>>,
        token: Option<Vec<u8>>,
        result_tx: oneshot::Sender<Result<TquicConnection, AsyncError>>,
    },
    /// Shut down the endpoint.
    Close,
}

/// A `Send`-safe async QUIC endpoint handle.
///
/// The underlying tquic `Endpoint` lives on a `LocalSet`. This handle
/// communicates with the driver via channels.
pub struct TquicEndpoint {
    /// Channel for sending commands to the driver event loop.
    cmd_tx: mpsc::Sender<EndpointCmd>,

    /// Receiver for incoming server-side connections.
    incoming_rx: mpsc::Receiver<TquicConnection>,

    /// The local address the endpoint is bound to.
    local_addr: SocketAddr,
}

impl TquicEndpoint {
    /// Create a new endpoint from pre-built channels.
    ///
    /// This is called by the driver during initialization.
    pub(crate) fn new(
        cmd_tx: mpsc::Sender<EndpointCmd>,
        incoming_rx: mpsc::Receiver<TquicConnection>,
        local_addr: SocketAddr,
    ) -> Self {
        Self {
            cmd_tx,
            incoming_rx,
            local_addr,
        }
    }

    /// Create a client endpoint bound to the given address.
    ///
    /// Spawns the driver event loop on a `LocalSet`. The returned
    /// handle can be used from any tokio task.
    pub async fn client(bind: SocketAddr, config: crate::Config) -> Result<Self, AsyncError> {
        super::driver::spawn_driver(bind, config, false).await
    }

    /// Create a server endpoint bound to the given address.
    ///
    /// Spawns the driver event loop on a `LocalSet`. The returned
    /// handle can be used from any tokio task.
    pub async fn server(bind: SocketAddr, config: crate::Config) -> Result<Self, AsyncError> {
        super::driver::spawn_driver(bind, config, true).await
    }

    /// Connect to a remote QUIC server.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<TquicConnection, AsyncError> {
        self.connect_inner(remote, server_name, None, None).await
    }

    /// Connect with 0-RTT using a saved session ticket and token.
    pub async fn connect_with_0rtt(
        &self,
        remote: SocketAddr,
        server_name: &str,
        session: &[u8],
        token: &[u8],
    ) -> Result<TquicConnection, AsyncError> {
        self.connect_inner(
            remote,
            server_name,
            Some(session.to_vec()),
            Some(token.to_vec()),
        )
        .await
    }

    /// Accept an incoming connection from a remote client.
    ///
    /// Returns `None` if the endpoint has been closed.
    pub async fn accept(&mut self) -> Option<TquicConnection> {
        self.incoming_rx.recv().await
    }

    /// Return the local address the endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shut down the endpoint.
    pub fn close(&self) {
        let _ = self.cmd_tx.try_send(EndpointCmd::Close);
    }

    /// Internal helper for connect variants.
    async fn connect_inner(
        &self,
        remote: SocketAddr,
        server_name: &str,
        session: Option<Vec<u8>>,
        token: Option<Vec<u8>>,
    ) -> Result<TquicConnection, AsyncError> {
        let (result_tx, result_rx) = oneshot::channel();
        self.cmd_tx
            .send(EndpointCmd::Connect {
                remote,
                server_name: server_name.to_string(),
                session,
                token,
                result_tx,
            })
            .await
            .map_err(|_| AsyncError::ChannelClosed)?;
        result_rx.await.map_err(|_| AsyncError::ChannelClosed)?
    }
}
