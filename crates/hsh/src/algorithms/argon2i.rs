// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Argon2i wrapper.
//!
//! **Roadmap note**: this wraps the unmaintained `argon2rs` crate and exposes
//! the Argon2**i** variant only. Phase 1 (issue #156) replaces it with the
//! RustCrypto `argon2` crate and adopts **Argon2id** as the default per
//! RFC 9106 §4. Until then, prefer this for backwards compatibility only.

use crate::error::Result;
use crate::models::hash_algorithm::HashingAlgorithm;
use argon2rs::argon2i_simple;
use serde::{Deserialize, Serialize};

/// Marker type for the Argon2i hashing algorithm.
///
/// Implements [`HashingAlgorithm`] for password hashing using Argon2i.
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
pub struct Argon2i;

impl HashingAlgorithm for Argon2i {
    /// Hashes a plaintext `password` using Argon2i with the provided `salt`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::Error::Hashing`] only if the underlying primitive fails,
    /// which `argon2i_simple` does not surface today — kept for forwards
    /// compatibility with the Phase 1 RustCrypto backend.
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        Ok(argon2i_simple(password, salt).into_iter().collect())
    }
}
