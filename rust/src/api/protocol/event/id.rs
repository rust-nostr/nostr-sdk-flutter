// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::ops::Deref;

use anyhow::Result;
use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

use super::tag::_Tag;
use crate::api::protocol::key::_PublicKey;

#[frb(name = "EventId")]
pub struct _EventId {
    pub(crate) inner: EventId,
}

impl Deref for _EventId {
    type Target = EventId;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl From<EventId> for _EventId {
    fn from(inner: EventId) -> Self {
        Self { inner }
    }
}

#[frb(sync)]
impl _EventId {
    pub fn new(
        public_key: &_PublicKey,
        created_at: u64,
        kind: u16,
        tags: &[_Tag],
        content: &str,
    ) -> Result<Self> {
        let created_at = Timestamp::from_secs(created_at);
        let kind = Kind::from_u16(kind);
        let tags: Tags = tags.iter().map(|t| t.inner.clone()).collect();
        Ok(Self {
            inner: EventId::new(public_key.deref(), &created_at, &kind, &tags, content),
        })
    }

    /// Try to parse event ID from `hex`, `bech32` or [NIP21](https://github.com/nostr-protocol/nips/blob/master/21.md) uri
    pub fn parse(id: &str) -> Result<Self> {
        Ok(Self {
            inner: EventId::parse(id)?,
        })
    }

    /// Parse from bytes
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: EventId::from_slice(bytes)?,
        })
    }

    /// Get bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.as_bytes().to_vec()
    }

    /// Serialize to hex
    pub fn to_hex(&self) -> String {
        self.inner.to_hex()
    }

    /// Serialize to bech32
    pub fn to_bech32(&self) -> Result<String> {
        Ok(self.inner.to_bech32()?)
    }

    /// Serialize as nostr URI
    pub fn to_nostr_uri(&self) -> Result<String> {
        Ok(self.inner.to_nostr_uri()?)
    }
}
