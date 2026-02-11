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

//! User-facing TquicEndpoint for the reactor pattern.
//!
//! Holds channel senders to communicate with the reactor task.
//! All operations are `Send + Sync` without any mutexes.

use std::net::SocketAddr;

use tokio::sync::{mpsc, oneshot};

use super::cmd::{ConnHandle, ControlCmd, DataCmd};
use super::error::AsyncError;
use super::reactor::{Reactor, ReactorChannels};
use super::reactor_connection::TquicConnection;
use crate::Config;

/// A `Send + Sync` async QUIC endpoint handle (reactor version).
///
/// Communicates with the reactor task via channels.
/// No mutexes are needed for any operation.
pub struct TquicEndpoint {
    /// Sender for control-plane commands.
    control_tx: mpsc::Sender<ControlCmd>,

    /// Sender for data-plane commands.
    data_tx: mpsc::Sender<DataCmd>,

    /// Local bind address.
    local_addr: SocketAddr,

    /// Receiver for incoming connections (server only).
    incoming_conn_rx: Option<mpsc::Receiver<ConnHandle>>,
}

impl TquicEndpoint {
    /// Create a client endpoint bound to the given address.
    pub async fn client(bind: SocketAddr, config: Config) -> Result<Self, AsyncError> {
        Self::create(bind, config, false).await
    }

    /// Create a server endpoint bound to the given address.
    pub async fn server(bind: SocketAddr, config: Config) -> Result<Self, AsyncError> {
        Self::create(bind, config, true).await
    }

    /// Internal endpoint creation (spawns the reactor task).
    async fn create(bind: SocketAddr, config: Config, is_server: bool) -> Result<Self, AsyncError> {
        let (reactor, channels) = Reactor::new(bind, config, is_server)?;
        let local_addr = reactor.local_addr();
        tokio::spawn(reactor.run());
        Ok(Self {
            control_tx: channels.control_tx,
            data_tx: channels.data_tx,
            local_addr,
            incoming_conn_rx: channels.incoming_conn_rx,
        })
    }

    /// Connect to a remote QUIC server.
    pub async fn connect(
        &self,
        remote: SocketAddr,
        server_name: &str,
    ) -> Result<TquicConnection, AsyncError> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(ControlCmd::Connect {
                remote,
                server_name: server_name.to_string(),
                session: None,
                token: None,
                tx,
            })
            .await
            .map_err(|_| AsyncError::ReactorGone)?;

        let handle = rx.await.map_err(|_| AsyncError::ReactorGone)??;
        Ok(TquicConnection::new(
            handle.conn_index,
            handle.remote_addr,
            self.control_tx.clone(),
            self.data_tx.clone(),
            handle.shared,
            handle.incoming_bi_rx,
            handle.incoming_uni_rx,
        ))
    }

    /// Accept an incoming connection (server only).
    ///
    /// Returns `None` if the endpoint has been closed.
    pub async fn accept(&mut self) -> Option<TquicConnection> {
        let rx = self.incoming_conn_rx.as_mut()?;
        let handle = rx.recv().await?;
        Some(TquicConnection::new(
            handle.conn_index,
            handle.remote_addr,
            self.control_tx.clone(),
            self.data_tx.clone(),
            handle.shared,
            handle.incoming_bi_rx,
            handle.incoming_uni_rx,
        ))
    }

    /// Return the local address the endpoint is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Shut down the endpoint.
    pub fn close(&self) {
        let _ = self.control_tx.try_send(ControlCmd::Shutdown);
    }
}
