// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use anyhow::Result;
use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

/// Secret key
#[frb(name = "SecretKey")]
pub struct _SecretKey {
    pub(crate) inner: SecretKey,
}

impl From<SecretKey> for _SecretKey {
    fn from(inner: SecretKey) -> Self {
        Self { inner }
    }
}

#[frb(sync)]
impl _SecretKey {
    /// Generate random secret key
    ///
    /// This constructor uses a random number generator that retrieves randomness from the operating system.
    pub fn generate() -> Self {
        Self {
            inner: SecretKey::generate(),
        }
    }

    /// Parse from `hex` or `bech32`
    pub fn parse(secret_key: &str) -> Result<Self> {
        Ok(Self {
            inner: SecretKey::parse(secret_key)?,
        })
    }

    /// Parse from bytes
    pub fn from_slice(secret_key: &[u8]) -> Result<Self> {
        Ok(Self {
            inner: SecretKey::from_slice(secret_key)?,
        })
    }

    /// Serialize to hex
    pub fn to_secret_hex(&self) -> String {
        self.inner.to_secret_hex()
    }

    /// Serialize to bech32
    pub fn to_bech32(&self) -> Result<String> {
        Ok(self.inner.to_bech32()?)
    }

    /// Serialize to bytes
    pub fn to_secret_bytes(&self) -> [u8; SecretKey::LEN] {
        self.inner.to_secret_bytes()
    }

    // TODO: add encrypt method
}
