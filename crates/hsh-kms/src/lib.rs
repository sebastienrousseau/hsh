#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # `hsh-kms` — pepper / KMS integration for `hsh`
//!
//! This crate provides the [`Pepper`] trait and a small set of
//! pluggable backends that let an application "pepper" its passwords
//! with a secret key held outside the password database — typically in
//! AWS KMS, Google Cloud KMS, Azure Key Vault, or HashiCorp Vault.
//!
//! ## The pepper pattern
//!
//! A *pepper* is a server-side secret applied to every password before
//! it is hashed. Unlike a per-password salt (which lives next to the
//! hash), the pepper is **the same for every password** and lives in a
//! separate trust boundary — usually a KMS / HSM that the password
//! database cannot read.
//!
//! Concretely, [`Pepper::apply`] computes
//! `HMAC-SHA-256(key_at(version), password)` and returns the 32-byte
//! tag, which the `hsh` crate then feeds into Argon2id / bcrypt /
//! scrypt as if it were the user's password.
//!
//! ### Why
//!
//! - **Defence in depth** — an attacker who steals only the password
//!   DB cannot brute-force credentials offline because they're missing
//!   the pepper.
//! - **Rotatable** — bump [`KeyVersion`] periodically; on each
//!   successful login under the old version, `hsh::api::verify_and_upgrade`
//!   re-hashes under the new version transparently.
//! - **Compliance** — PCI DSS 4.0 §3.5.1.1 effectively requires this
//!   for PAN hashing; many SOC 2 / ISO 27001 auditors expect it for
//!   password storage too.
//!
//! ## Backends
//!
//! - [`LocalPepper`] — keys held in process memory. Safe for tests,
//!   short-lived workloads, or apps without a KMS.
//! - `aws::fetch_pepper` (feature `aws-kms`) — fetch a key from AWS
//!   KMS via the `aws-sdk-kms` crate, returning a [`LocalPepper`]
//!   snapshot.
//! - `gcp::fetch_pepper` (feature `gcp-kms`) — likewise for GCP Cloud
//!   KMS.
//! - `azure::fetch_pepper` (feature `azure-key-vault`).
//! - `vault::fetch_pepper` (feature `hashicorp-vault`).
//!
//! Provider implementations are currently **stubs** that document the
//! intended interface; the real network calls land incrementally as
//! they get integration-tested against the cloud providers.
//!
//! ## Example
//!
//! ```
//! use hsh_kms::{KeyVersion, LocalPepper, Pepper};
//!
//! let pepper = LocalPepper::builder()
//!     .add(KeyVersion::new(1), b"the-server-pepper-v1-DO-NOT-COMMIT".to_vec())
//!     .current(KeyVersion::new(1))
//!     .build()
//!     .unwrap();
//!
//! let tag = pepper.apply(KeyVersion::new(1), b"correct horse").unwrap();
//! assert_eq!(tag.len(), 32);
//! ```

pub mod error;

#[cfg(feature = "aws-kms")]
pub mod aws;
#[cfg(feature = "azure-key-vault")]
pub mod azure;
#[cfg(feature = "gcp-kms")]
pub mod gcp;
#[cfg(feature = "hashicorp-vault")]
pub mod vault;

use std::collections::BTreeMap;
use std::fmt;

use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroize;

pub use error::PepperError;

/// A monotonically increasing key version used to identify which pepper
/// was applied to a given password hash. Stored alongside the hash so
/// rotation is non-destructive.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct KeyVersion(u32);

impl KeyVersion {
    /// Constructs a `KeyVersion`.
    #[must_use]
    pub const fn new(v: u32) -> Self {
        Self(v)
    }

    /// Returns the underlying `u32`.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl Default for KeyVersion {
    fn default() -> Self {
        Self(1)
    }
}

impl fmt::Display for KeyVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A pepper provider — produces an HMAC-SHA-256 tag over the password
/// keyed by the secret material for a given [`KeyVersion`].
///
/// Implementations must be `Send + Sync` so a `Policy` carrying a
/// pepper can be shared across worker threads.
pub trait Pepper: fmt::Debug + Send + Sync {
    /// Computes `HMAC-SHA-256(key_at(version), password)` and returns
    /// the 32-byte tag. Errors if the requested `version` is not
    /// available in this provider.
    ///
    /// # Errors
    ///
    /// Returns [`PepperError::UnknownVersion`] if the version isn't
    /// stored, or [`PepperError::Backend`] if the backend (KMS) fails.
    fn apply(
        &self,
        version: KeyVersion,
        password: &[u8],
    ) -> Result<[u8; 32], PepperError>;

    /// Returns the key version to use for *new* hashes. Older versions
    /// remain usable via [`Pepper::apply`] for verifying existing
    /// hashes; rotation is handled by `hsh::api::verify_and_upgrade`.
    fn current(&self) -> KeyVersion;
}

/// In-memory pepper provider. **Keys live in process memory** — use a
/// real KMS for production secrets.
pub struct LocalPepper {
    keys: BTreeMap<KeyVersion, Vec<u8>>,
    current: KeyVersion,
}

impl LocalPepper {
    /// Starts building a `LocalPepper`.
    #[must_use]
    pub fn builder() -> LocalPepperBuilder {
        LocalPepperBuilder::default()
    }

    /// Returns the set of key versions held in memory, sorted ascending.
    #[must_use]
    pub fn versions(&self) -> Vec<KeyVersion> {
        self.keys.keys().copied().collect()
    }
}

impl Pepper for LocalPepper {
    fn apply(
        &self,
        version: KeyVersion,
        password: &[u8],
    ) -> Result<[u8; 32], PepperError> {
        let key = self
            .keys
            .get(&version)
            .ok_or(PepperError::UnknownVersion(version))?;

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
            .map_err(|e| PepperError::Backend(e.to_string()))?;
        mac.update(password);
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        Ok(out)
    }

    fn current(&self) -> KeyVersion {
        self.current
    }
}

impl fmt::Debug for LocalPepper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose the raw key bytes — only metadata.
        f.debug_struct("LocalPepper")
            .field("versions", &self.keys.keys().collect::<Vec<_>>())
            .field("current", &self.current)
            .finish()
    }
}

impl Drop for LocalPepper {
    fn drop(&mut self) {
        for k in self.keys.values_mut() {
            k.zeroize();
        }
    }
}

/// Builder for [`LocalPepper`].
#[derive(Debug, Default)]
pub struct LocalPepperBuilder {
    keys: BTreeMap<KeyVersion, Vec<u8>>,
    current: Option<KeyVersion>,
}

impl LocalPepperBuilder {
    /// Registers a key at `version`. Keys should be at least 32 bytes
    /// of cryptographic-quality entropy (typically the OS CSPRNG).
    #[must_use]
    pub fn add(mut self, version: KeyVersion, key: Vec<u8>) -> Self {
        let _ = self.keys.insert(version, key);
        self
    }

    /// Sets the current key version used for new hashes. Must match
    /// one of the versions registered via [`add`](Self::add).
    #[must_use]
    pub fn current(mut self, version: KeyVersion) -> Self {
        self.current = Some(version);
        self
    }

    /// Finalises the builder.
    ///
    /// # Errors
    ///
    /// - [`PepperError::EmptyKeyset`] if no keys were added.
    /// - [`PepperError::UnknownVersion`] if the `current` version
    ///   isn't in the keyset.
    /// - [`PepperError::KeyTooShort`] if any registered key is shorter
    ///   than 16 bytes (a sanity floor — production keys should be 32+).
    pub fn build(self) -> Result<LocalPepper, PepperError> {
        if self.keys.is_empty() {
            return Err(PepperError::EmptyKeyset);
        }
        for (v, k) in &self.keys {
            if k.len() < 16 {
                return Err(PepperError::KeyTooShort {
                    version: *v,
                    actual: k.len(),
                    minimum: 16,
                });
            }
        }
        let current = self
            .current
            .or_else(|| self.keys.keys().last().copied())
            .ok_or(PepperError::EmptyKeyset)?;
        if !self.keys.contains_key(&current) {
            return Err(PepperError::UnknownVersion(current));
        }
        Ok(LocalPepper {
            keys: self.keys,
            current,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> LocalPepper {
        LocalPepper::builder()
            .add(
                KeyVersion::new(1),
                b"v1-pepper-bytes-aaaaaaaa".to_vec(),
            )
            .add(
                KeyVersion::new(2),
                b"v2-pepper-bytes-bbbbbbbb".to_vec(),
            )
            .current(KeyVersion::new(2))
            .build()
            .unwrap()
    }

    #[test]
    fn apply_returns_32_bytes() {
        let p = fixture();
        let tag = p.apply(KeyVersion::new(1), b"password").unwrap();
        assert_eq!(tag.len(), 32);
    }

    #[test]
    fn different_versions_produce_different_tags() {
        let p = fixture();
        let a = p.apply(KeyVersion::new(1), b"password").unwrap();
        let b = p.apply(KeyVersion::new(2), b"password").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn unknown_version_errors() {
        let p = fixture();
        let err =
            p.apply(KeyVersion::new(99), b"password").unwrap_err();
        assert!(matches!(err, PepperError::UnknownVersion(_)));
    }

    #[test]
    fn current_is_highest_when_not_set() {
        let p = LocalPepper::builder()
            .add(KeyVersion::new(1), b"key-1-aaaaaaaaaaaaa".to_vec())
            .add(KeyVersion::new(7), b"key-7-bbbbbbbbbbbbb".to_vec())
            .build()
            .unwrap();
        assert_eq!(p.current(), KeyVersion::new(7));
    }

    #[test]
    fn short_keys_rejected() {
        let r = LocalPepper::builder()
            .add(KeyVersion::new(1), b"too-short".to_vec())
            .build();
        assert!(matches!(r, Err(PepperError::KeyTooShort { .. })));
    }

    #[test]
    fn empty_keyset_rejected() {
        let r = LocalPepper::builder().build();
        assert!(matches!(r, Err(PepperError::EmptyKeyset)));
    }
}
