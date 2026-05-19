// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Versioned `Policy` describing the primary algorithm and per-algorithm
//! parameters used by the high-level [`crate::api`] surface.
//!
//! Presets:
//!
//! - [`Policy::owasp_minimum_2025`] — sensible web-app default
//!   (Argon2id, `m = 19 456 KiB`, `t = 2`, `p = 1`).
//! - [`Policy::rfc9106_first_recommended`] — security-critical servers
//!   with ample memory (Argon2id, `m = 2^21`, `t = 1`, `p = 4`).

use crate::algorithms::argon2id;
use crate::algorithms::bcrypt::BcryptParams;
use crate::algorithms::scrypt::ScryptParams;
use argon2::Params as Argon2Params;
#[cfg(feature = "pepper")]
use std::sync::Arc;

/// Which algorithm a [`Policy`] uses for *new* hashes.
///
/// Verification accepts any of the supported algorithms (Argon2i/d/id,
/// bcrypt, scrypt) regardless of the policy's primary.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PrimaryAlgorithm {
    /// **Argon2id** — recommended; the only sensible default for
    /// new password hashes per RFC 9106 §4.
    Argon2id,
    /// **Bcrypt** — useful for ecosystems already on bcrypt.
    Bcrypt,
    /// **Scrypt** — memory-hard, simpler parameter story than Argon2.
    Scrypt,
}

/// Versioned policy snapshot: the algorithm to use for new hashes plus
/// the parameter ladders for every supported variant.
///
/// When compiled with the `pepper` feature, [`Policy::pepper`] carries
/// an optional [`hsh_kms::Pepper`] provider that the high-level API
/// applies transparently via HMAC-SHA-256 before delegating to the KDF.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Algorithm used by [`crate::api::hash`] to mint new hashes.
    pub primary: PrimaryAlgorithm,
    /// Argon2 parameters (shared across Argon2id / Argon2i / Argon2d).
    pub argon2: Argon2Params,
    /// Bcrypt parameters.
    pub bcrypt: BcryptParams,
    /// Scrypt parameters.
    pub scrypt: ScryptParams,
    /// Optional server-side pepper applied before hashing. Requires
    /// the `pepper` feature.
    #[cfg(feature = "pepper")]
    pub pepper: Option<Arc<dyn hsh_kms::Pepper>>,
}

impl Policy {
    /// OWASP Password Storage Cheat Sheet 2025 minimum for all three KDFs.
    ///
    /// - **Argon2id**: `m = 19 456 KiB (19 MiB)`, `t = 2`, `p = 1`
    /// - **Bcrypt**: `cost = 10`, no pre-hash
    /// - **Scrypt**: `N = 2^17`, `r = 8`, `p = 1`
    pub fn owasp_minimum_2025() -> Self {
        Self {
            primary: PrimaryAlgorithm::Argon2id,
            argon2: argon2id::owasp_minimum_2025(),
            bcrypt: BcryptParams::new(10),
            scrypt: ScryptParams::default(),
            #[cfg(feature = "pepper")]
            pepper: None,
        }
    }

    /// RFC 9106 §4 first-recommended for Argon2id: `m = 2^21 (2 GiB)`,
    /// `t = 1`, `p = 4`. Bcrypt and scrypt fall back to OWASP-2025.
    pub fn rfc9106_first_recommended() -> Self {
        Self {
            primary: PrimaryAlgorithm::Argon2id,
            argon2: argon2id::rfc9106_first_recommended(),
            bcrypt: BcryptParams::new(10),
            scrypt: ScryptParams::default(),
            #[cfg(feature = "pepper")]
            pepper: None,
        }
    }

    /// Attaches a pepper provider to this policy and returns the
    /// updated value.
    ///
    /// New hashes will be peppered with `provider.current()`. Old
    /// hashes carrying earlier key versions remain verifiable, and
    /// [`crate::api::verify_and_upgrade`] will signal `needs_rehash`
    /// when an old version is detected.
    #[cfg(feature = "pepper")]
    #[must_use]
    pub fn with_pepper(
        mut self,
        provider: Arc<dyn hsh_kms::Pepper>,
    ) -> Self {
        self.pepper = Some(provider);
        self
    }

    /// Returns `true` if `stored_params` are at least as strong as the
    /// current policy's Argon2 params. Used by [`crate::api::verify_and_upgrade`]
    /// to decide whether a successful verify should trigger a rehash.
    pub(crate) fn argon2_satisfies(
        &self,
        stored: &Argon2Params,
    ) -> bool {
        stored.m_cost() >= self.argon2.m_cost()
            && stored.t_cost() >= self.argon2.t_cost()
            && stored.p_cost() >= self.argon2.p_cost()
            && stored.output_len() == self.argon2.output_len()
    }
}

impl Default for Policy {
    fn default() -> Self {
        Self::owasp_minimum_2025()
    }
}
