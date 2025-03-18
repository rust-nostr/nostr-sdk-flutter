// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

#[cfg(not(target_arch = "wasm32"))]
use std::net::SocketAddr;
use std::ops::Deref;

use anyhow::Result;
use flutter_rust_bridge::frb;
#[cfg(target_arch = "wasm32")]
use nostr_sdk::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use nostr_sdk::prelude::{self, *};

use crate::api::relay::options::ConnectionMode;

#[derive(Clone)]
#[frb(name = "ClientOptions")]
pub struct _ClientOptions {
    pub(super) inner: Options,
}

impl Deref for _ClientOptions {
    type Target = Options;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<Options> for _ClientOptions {
    fn from(inner: Options) -> Self {
        Self { inner }
    }
}

#[frb(sync)]
impl _ClientOptions {
    pub fn new() -> Self {
        Self {
            inner: Options::new(),
        }
    }

    /// Automatically start connection with relays (default: false)
    ///
    /// When set to `true`, there isn't the need of calling the connect methods.
    pub fn autoconnect(&self, val: bool) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.autoconnect(val);
        builder
    }

    // pub fn req_filters_chunk_size(&self, req_filters_chunk_size: u8) -> Self {
    //     let mut builder = self.clone();
    //     builder.inner = builder.inner.req_filters_chunk_size(req_filters_chunk_size);
    //     builder
    // }

    /// Auto authenticate to relays (default: true)
    ///
    /// <https://github.com/nostr-protocol/nips/blob/master/42.md>
    pub fn automatic_authentication(&self, enabled: bool) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.automatic_authentication(enabled);
        builder
    }

    /// Enable gossip model (default: false)
    pub fn gossip(&self, enabled: bool) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.gossip(enabled);
        builder
    }

    /// Connection
    pub fn connection(&self, connection: &_Connection) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = self.clone();
            builder.inner = builder.inner.connection(connection.inner.clone());
            builder
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = connection;
            self.clone()
        }
    }

    // /// Set custom relay limits
    // pub fn relay_limits(&self, limits: &RelayLimits) -> Self {
    //     let mut builder = self.clone();
    //     builder.inner = builder.inner.relay_limits(limits.deref().clone());
    //     builder
    // }
    //
    // /// Set max latency (default: None)
    // ///
    // /// Relays with an avg. latency greater that this value will be skipped.
    // pub fn max_avg_latency(&self, max: Duration) -> Self {
    //     let mut builder = self.clone();
    //     builder.inner = builder.inner.max_avg_latency(max);
    //     builder
    // }
    //
    // /// Set filtering mode (default: blacklist)
    // pub fn filtering_mode(&self, mode: RelayFilteringMode) -> Self {
    //     let mut builder = self.clone();
    //     builder.inner = builder.inner.filtering_mode(mode.into());
    //     builder
    // }
}

/// Connection target
pub enum ConnectionTarget {
    /// Use proxy for all relays
    All,
    /// Use proxy only for `.onion` relays
    Onion,
}

#[cfg(not(target_arch = "wasm32"))]
impl From<ConnectionTarget> for prelude::ConnectionTarget {
    fn from(value: ConnectionTarget) -> Self {
        match value {
            ConnectionTarget::All => Self::All,
            ConnectionTarget::Onion => Self::Onion,
        }
    }
}

/// Connection
#[derive(Clone)]
#[frb(name = "Connection")]
pub struct _Connection {
    #[cfg(not(target_arch = "wasm32"))]
    inner: Connection,
    #[cfg(target_arch = "wasm32")]
    inner: (),
}

#[frb(sync)]
impl _Connection {
    pub fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            inner: Connection::default(),
            #[cfg(target_arch = "wasm32")]
            inner: (),
        }
    }

    /// Set connection mode (default: direct)
    pub fn mode(&self, mode: ConnectionMode) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mode: prelude::ConnectionMode = mode.try_into()?;
            let mut builder = self.clone();
            builder.inner = builder.inner.mode(mode);
            return Ok(builder);
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = mode;
            Ok(self.clone())
        }
    }

    /// Set connection target (default: all)
    pub fn target(&self, target: ConnectionTarget) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = self.clone();
            builder.inner = builder.inner.target(target.into());
            builder
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = target;
            self.clone()
        }
    }

    /// Set proxy (ex. `127.0.0.1:9050`)
    pub fn addr(&self, addr: &str) -> Result<Self> {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = self.clone();
            let addr: SocketAddr = addr.parse()?;
            builder.inner = builder.inner.proxy(addr);
            return Ok(builder);
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = addr;
            Ok(self.clone())
        }
    }

    /// Use embedded tor client
    ///
    /// This not work on `android` and/or `ios` targets.
    /// Use [`Connection::embedded_tor_with_path`] instead.
    pub fn embedded_tor(&self) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = self.clone();
            builder.inner = builder.inner.embedded_tor();
            builder
        }

        #[cfg(target_arch = "wasm32")]
        self.clone()
    }

    /// Use embedded tor client
    ///
    /// Specify a path where to store data
    pub fn embedded_tor_with_path(&self, data_path: String) -> Self {
        #[cfg(not(target_arch = "wasm32"))]
        {
            let mut builder = self.clone();
            builder.inner = builder.inner.embedded_tor_with_path(data_path);
            builder
        }

        #[cfg(target_arch = "wasm32")]
        {
            let _ = data_path;
            self.clone()
        }
    }
}
