// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Argon2 wrapper built on the RustCrypto [`argon2`] crate.
//!
//! Supports Argon2i, Argon2d, and Argon2id. **Argon2id is the
//! recommended default** per RFC 9106 §4; Argon2i is kept for
//! verification of legacy hashes only (it has known time–memory
//! trade-off attacks when used standalone for password hashing).

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

/// Default output length in bytes for raw Argon2 hashes (256-bit tag).
pub const DEFAULT_OUTPUT_LEN: usize = 32;

/// OWASP-2025 minimum recommended parameters for Argon2id on web servers:
/// `m = 19 456 KiB`, `t = 2`, `p = 1`.
pub fn owasp_minimum_2025() -> Params {
    Params::new(19_456, 2, 1, Some(DEFAULT_OUTPUT_LEN))
        .expect("OWASP-2025 minimum params must be valid")
}

/// RFC 9106 §4 first-recommended parameters: `m = 2^21`, `t = 1`, `p = 4`.
/// Use this for security-critical servers with ample memory.
pub fn rfc9106_first_recommended() -> Params {
    Params::new(1 << 21, 1, 4, Some(DEFAULT_OUTPUT_LEN))
        .expect("RFC 9106 first-recommended params must be valid")
}

/// Marker type for Argon2id — the recommended variant.
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
pub struct Argon2id;

/// Marker type for Argon2i — verify-only for legacy hashes.
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
pub struct Argon2i;

/// Marker type for Argon2d — exposed for completeness.
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
pub struct Argon2d;

fn hash_with(
    algo: Algorithm,
    params: Params,
    password: &str,
    salt: &str,
) -> Result<Vec<u8>> {
    let engine = Argon2::new(algo, Version::V0x13, params);
    let mut out = vec![0u8; DEFAULT_OUTPUT_LEN];
    engine
        .hash_password_into(
            password.as_bytes(),
            salt.as_bytes(),
            &mut out,
        )
        .map_err(|e| Error::Hashing(e.to_string()))?;
    Ok(out)
}

impl HashingAlgorithm for Argon2id {
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        hash_with(
            Algorithm::Argon2id,
            owasp_minimum_2025(),
            password,
            salt,
        )
    }
}

impl HashingAlgorithm for Argon2i {
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        hash_with(
            Algorithm::Argon2i,
            owasp_minimum_2025(),
            password,
            salt,
        )
    }
}

impl HashingAlgorithm for Argon2d {
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        hash_with(
            Algorithm::Argon2d,
            owasp_minimum_2025(),
            password,
            salt,
        )
    }
}

/// Verifies `password` against `stored` using the given Argon2 variant
/// and parameters. Constant-time compare via `subtle` is performed
/// inside RustCrypto's `argon2`.
pub fn verify(
    algo: Algorithm,
    params: Params,
    password: &str,
    salt: &str,
    stored: &[u8],
) -> Result<bool> {
    use subtle::ConstantTimeEq;

    if stored.len() != DEFAULT_OUTPUT_LEN {
        // Parameter mismatch is also a verification failure.
        return Ok(false);
    }
    let mut calculated = vec![0u8; stored.len()];
    Argon2::new(algo, Version::V0x13, params)
        .hash_password_into(
            password.as_bytes(),
            salt.as_bytes(),
            &mut calculated,
        )
        .map_err(|e| Error::Hashing(e.to_string()))?;
    Ok(bool::from(calculated.ct_eq(stored)))
}
