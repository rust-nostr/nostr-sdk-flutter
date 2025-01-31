// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::ops::Deref;

use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

use super::_Client;
use super::options::_ClientOptions;
use crate::api::database::_NostrDatabase;
use crate::api::protocol::signer::_NostrSigner;

#[derive(Clone)]
#[frb(name = "ClientBuilder")]
pub struct _ClientBuilder {
    inner: ClientBuilder,
}

impl From<ClientBuilder> for _ClientBuilder {
    fn from(inner: ClientBuilder) -> Self {
        Self { inner }
    }
}

#[frb(sync)]
impl _ClientBuilder {
    /// New client builder
    pub fn new() -> Self {
        Self {
            inner: ClientBuilder::new(),
        }
    }

    /// Set signer
    pub fn signer(&self, signer: &_NostrSigner) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.signer(signer.inner.clone());
        builder
    }

    /// Set database
    pub fn database(&self, database: &_NostrDatabase) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.database(database.deref().clone());
        builder
    }

    /// Set opts
    pub fn opts(&self, opts: &_ClientOptions) -> Self {
        let mut builder = self.clone();
        builder.inner = builder.inner.opts(opts.inner.clone());
        builder
    }

    /// Build client
    pub fn build(self) -> _Client {
        self.inner.build().into()
    }
}
