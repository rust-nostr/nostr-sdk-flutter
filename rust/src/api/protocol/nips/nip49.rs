// Copyright (c) 2022-2023 Yuki Kishimoto
// Copyright (c) 2023-2024 Rust Nostr Developers
// Distributed under the MIT software license

use std::ops::Deref;

use anyhow::Result;
use flutter_rust_bridge::frb;
use nostr::nips::nip49::Version;
use nostr_sdk::prelude::*;

use crate::api::protocol::key::_SecretKey;

/// Encrypted Secret Key version (NIP49)
pub enum EncryptedSecretKeyVersion {
    V2,
}

impl From<Version> for EncryptedSecretKeyVersion {
    fn from(value: Version) -> Self {
        match value {
            Version::V2 => Self::V2,
        }
    }
}

/// Key security
pub enum EncryptedSecretKeySecurity {
    /// The key has been known to have been handled insecurely (stored unencrypted, cut and paste unencrypted, etc)
    Weak,
    /// The key has NOT been known to have been handled insecurely (stored encrypted, cut and paste encrypted, etc)
    Medium,
    /// The client does not track this data
    Unknown,
}

impl From<KeySecurity> for EncryptedSecretKeySecurity {
    fn from(value: KeySecurity) -> Self {
        match value {
            KeySecurity::Weak => Self::Weak,
            KeySecurity::Medium => Self::Medium,
            KeySecurity::Unknown => Self::Unknown,
        }
    }
}

impl From<EncryptedSecretKeySecurity> for KeySecurity {
    fn from(value: EncryptedSecretKeySecurity) -> Self {
        match value {
            EncryptedSecretKeySecurity::Weak => Self::Weak,
            EncryptedSecretKeySecurity::Medium => Self::Medium,
            EncryptedSecretKeySecurity::Unknown => Self::Unknown,
        }
    }
}

/// Encrypted Secret Key
#[frb(name = "EncryptedSecretKey")]
pub struct _EncryptedSecretKey {
    inner: EncryptedSecretKey,
}

impl From<EncryptedSecretKey> for _EncryptedSecretKey {
    fn from(inner: EncryptedSecretKey) -> Self {
        Self { inner }
    }
}

#[frb(sync)]
impl _EncryptedSecretKey {
    /// Encrypt secret key
    pub fn new(
        secret_key: &_SecretKey,
        password: &str,
        log_n: u8,
        key_security: EncryptedSecretKeySecurity,
    ) -> Result<Self> {
        Ok(Self {
            inner: EncryptedSecretKey::new(
                secret_key.deref(),
                password,
                log_n,
                key_security.into(),
            )?,
        })
    }

    /// Parse from bech32
    pub fn from_bech32(bech32: &str) -> Result<Self> {
        Ok(Self {
            inner: EncryptedSecretKey::from_bech32(bech32)?,
        })
    }

    /// Get encrypted secret key version
    pub fn version(&self) -> EncryptedSecretKeyVersion {
        self.inner.version().into()
    }

    /// Get encrypted secret key security
    pub fn key_security(&self) -> EncryptedSecretKeySecurity {
        self.inner.key_security().into()
    }

    /// Decrypt secret key
    pub fn decrypt(&self, password: &str) -> Result<_SecretKey> {
        Ok(self.inner.decrypt(password)?.into())
    }

    /// Serialize to bech32
    pub fn to_bech32(&self) -> Result<String> {
        Ok(self.inner.to_bech32()?)
    }
}
