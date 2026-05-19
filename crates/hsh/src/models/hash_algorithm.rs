// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::error::Result;
use serde::{Deserialize, Serialize};

/// The supported password hashing algorithms.
///
/// `Argon2id` is the recommended default per RFC 9106 §4. Argon2i is
/// retained for verifying legacy hashes; Argon2d is exposed for
/// completeness but rarely the right choice for password hashing.
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
#[non_exhaustive]
pub enum HashAlgorithm {
    /// **Argon2id** — recommended for new password hashes
    /// (RFC 9106 §4 — hybrid of Argon2i + Argon2d).
    Argon2id,

    /// **Argon2i** — verify-only for legacy hashes. Has known
    /// time–memory trade-off attacks when used standalone for password
    /// hashing; do not use for new hashes.
    Argon2i,

    /// **Argon2d** — exposed for completeness; vulnerable to
    /// side-channel attacks. Not recommended for password hashing.
    Argon2d,

    /// **Bcrypt** — Blowfish-based KDF. 72-byte input ceiling enforced
    /// by [`crate::algorithms::bcrypt`].
    Bcrypt,

    /// **Scrypt** — memory-hard KDF. Default params follow OWASP-2025
    /// (`N = 2^17`, `r = 8`, `p = 1`).
    Scrypt,
}

/// Generic password-hashing trait.
///
/// The primary consumer is [`crate::models::hash::Hash`], which uses it
/// to dispatch to a concrete algorithm.
pub trait HashingAlgorithm {
    /// Hashes a plaintext `password` using a specific `salt`.
    ///
    /// Returns the raw hash bytes, or a [`crate::error::Error`]
    /// describing the failure.
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>>;
}
