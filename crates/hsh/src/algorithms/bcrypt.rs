// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Bcrypt wrapper.
//!
//! **Roadmap note**: Phase 1 (issue #158) introduces the 72-byte-input
//! safety rail (CVE-2025-22228 class). Today this wrapper still accepts
//! arbitrary lengths and relies on the underlying `bcrypt` crate's silent
//! truncation. Do not feed `>72` bytes in security-critical paths.

use crate::error::Result;
use crate::models::hash_algorithm::HashingAlgorithm;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};

/// Marker type for the Bcrypt hashing algorithm.
///
/// # Examples
///
/// ```
/// use hsh::algorithms::bcrypt::Bcrypt;
/// use hsh::models::hash_algorithm::HashingAlgorithm;
///
/// let hashed = Bcrypt::hash_password("supersecret", "ignored-salt").unwrap();
/// assert!(!hashed.is_empty());
/// ```
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
    /// Hashes a plaintext `password` using bcrypt at [`DEFAULT_COST`].
    ///
    /// The `_salt` argument is ignored — bcrypt generates its own salt.
    fn hash_password(password: &str, _salt: &str) -> Result<Vec<u8>> {
        hash(password, DEFAULT_COST)
            .map_err(|e| crate::error::Error::Hashing(e.to_string()))
            .map(String::into_bytes)
    }
}
