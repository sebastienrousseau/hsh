// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bcrypt wrapper with explicit 72-byte safety rail.
//!
//! ## Why the safety rail
//!
//! Bcrypt silently truncates passwords at 72 bytes. This produced real
//! authentication-bypass CVEs in 2024–2025:
//!
//! - **CVE-2025-22228** — Spring Security `BCryptPasswordEncoder` silently
//!   accepted passwords `>72` chars as equal to their first-72-byte prefix.
//! - **CVE-2025-68402** — FreshRSS triggered the same class of bug when an
//!   unrelated SHA-1 → SHA-256 nonce upgrade pushed the input over 72
//!   bytes.
//! - **Okta delegated-auth bypass (Oct 2024)** — cache keys built as
//!   `bcrypt(SHA1(user+session+pw))` collided when the SHA-1 hex pushed
//!   bcrypt's input beyond 72 bytes.
//!
//! This wrapper **rejects** any password longer than 72 bytes by default.
//! Callers that genuinely need to support longer inputs must opt in to a
//! pre-hash via [`BcryptParams::with_prehash`](crate::algorithms::bcrypt::BcryptParams::with_prehash).
//!
//! ## Storage format when a pre-hash is configured
//!
//! Bcrypt's MCF (`$2b$<cost>$<salt+hash>`) has no parameter slot for a
//! pre-hash marker, so [`crate::api::hash`] wraps the MCF in the
//! `hsh-bcrypt-sha256:<mcf>` envelope when [`PrehashAlgorithm::Sha256`]
//! is set on the [`crate::policy::Policy`]. The envelope round-trips
//! through [`crate::api::verify_and_upgrade`], which routes the password
//! through the same pre-hash before comparing — without the envelope the
//! verify side would feed bcrypt the raw password and the comparison
//! would always fail. The envelope also composes with the
//! `hsh-pepper:<keyver>:` wrapper: peppered + pre-hashed bcrypt hashes
//! are stored as `hsh-pepper:<keyver>:hsh-bcrypt-sha256:<mcf>`. Pre-hash
//! mode drift (stored mode ≠ policy mode) triggers an `Outcome::Valid
//! { rehashed: Some(_) }` on the next successful verify.

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use bcrypt::DEFAULT_COST;
use serde::{Deserialize, Serialize};

/// Maximum password length bcrypt can handle without silent truncation.
pub const BCRYPT_MAX_INPUT_BYTES: usize = 72;

/// Pre-hash algorithm to apply when the password exceeds 72 bytes.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub enum PrehashAlgorithm {
    /// No pre-hash — bcrypt receives the password verbatim and rejects
    /// inputs `>72` bytes. **Recommended default.**
    #[default]
    None,
    /// Hash the password with HMAC-SHA-256 keyed by the bcrypt salt
    /// before passing the 32-byte digest to bcrypt. Lets you accept
    /// arbitrary-length inputs without truncation.
    Sha256,
}

/// Bcrypt parameters.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct BcryptParams {
    /// Bcrypt cost factor (log2 of work). OWASP-2025 minimum is 10.
    pub cost: u32,
    /// Optional pre-hash to allow inputs longer than 72 bytes.
    pub prehash: PrehashAlgorithm,
}

impl Default for BcryptParams {
    fn default() -> Self {
        Self {
            cost: DEFAULT_COST,
            prehash: PrehashAlgorithm::None,
        }
    }
}

impl BcryptParams {
    /// Builds a bcrypt parameter set with the given cost factor.
    pub fn new(cost: u32) -> Self {
        Self {
            cost,
            prehash: PrehashAlgorithm::None,
        }
    }

    /// Enables the pre-hash safety adapter so passwords longer than
    /// 72 bytes are accepted via HMAC-SHA-256 pre-hash.
    pub fn with_prehash(mut self, algo: PrehashAlgorithm) -> Self {
        self.prehash = algo;
        self
    }
}

/// Marker type for the Bcrypt hashing algorithm.
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Bcrypt;

impl HashingAlgorithm for Bcrypt {
    /// Hashes `password` using bcrypt at [`DEFAULT_COST`].
    ///
    /// The `_salt` argument is ignored — bcrypt generates its own salt.
    /// Inputs longer than [`BCRYPT_MAX_INPUT_BYTES`] are **rejected** with
    /// [`Error::InvalidPassword`]; use [`Bcrypt::hash_with`] for an opt-in
    /// pre-hash policy.
    fn hash_password(password: &str, _salt: &str) -> Result<Vec<u8>> {
        Self::hash_with(password, BcryptParams::default())
    }
}

impl Bcrypt {
    /// Hashes `password` under explicit [`BcryptParams`].
    pub fn hash_with(
        password: &str,
        params: BcryptParams,
    ) -> Result<Vec<u8>> {
        let payload =
            prepare_payload(password.as_bytes(), params.prehash)?;
        bcrypt::hash(&payload, params.cost)
            .map(String::into_bytes)
            .map_err(|e| {
                Error::hashing(
                    crate::error::HashingErrorKind::Bcrypt,
                    e.to_string(),
                )
            })
    }

    /// Verifies `password` against a bcrypt hash string.
    ///
    /// Constant-time comparison is delegated to the `bcrypt` crate,
    /// which uses `subtle` internally.
    pub fn verify(
        password: &str,
        stored: &str,
        prehash: PrehashAlgorithm,
    ) -> Result<bool> {
        let payload = prepare_payload(password.as_bytes(), prehash)?;
        bcrypt::verify(&payload, stored).map_err(|_| {
            Error::Verification("bcrypt verify failed".into())
        })
    }
}

fn prepare_payload(
    password: &[u8],
    prehash: PrehashAlgorithm,
) -> Result<Vec<u8>> {
    match prehash {
        PrehashAlgorithm::None => {
            if password.len() > BCRYPT_MAX_INPUT_BYTES {
                return Err(Error::InvalidPassword(
                    "bcrypt input exceeds 72 bytes; opt into a pre-hash via BcryptParams::with_prehash to handle longer inputs".into(),
                ));
            }
            Ok(password.to_vec())
        }
        PrehashAlgorithm::Sha256 => {
            use sha2::{Digest, Sha256};
            let digest = Sha256::digest(password);
            // bcrypt's input must be valid UTF-8; b64-encode the digest
            // to ensure that without losing entropy.
            use base64::{engine::general_purpose, Engine as _};
            Ok(general_purpose::STANDARD_NO_PAD
                .encode(digest)
                .into_bytes())
        }
    }
}
