// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::ops::Deref;

use anyhow::Result;
use flutter_rust_bridge::frb;
use nostr_sdk::prelude::*;

use crate::api::protocol::nips::nip49::_EncryptedSecretKey;

/// Secret key
#[frb(name = "SecretKey")]
pub struct _SecretKey {
    pub(crate) inner: SecretKey,
}

impl Deref for _SecretKey {
    type Target = SecretKey;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
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

    /// Encrypt secret key
    ///
    /// By default, `LOG_N` is set to `16` and `EncryptedSecretKeySecurity` to `Unknown`.
    /// To use custom values, check `EncryptedSecretKey`.
    pub fn encrypt(&self, password: &str) -> Result<_EncryptedSecretKey> {
        Ok(self.inner.encrypt(password)?.into())
    }
}
