// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Scrypt wrapper with configurable parameters.
//!
//! Default parameters follow the OWASP Password Storage Cheat Sheet 2025
//! minimum recommendation: `N = 2^17 (131 072)`, `r = 8`, `p = 1`,
//! `dkLen = 64`. The previous default of `N = 2^14` is **below** the
//! OWASP minimum and should not be used in new deployments.

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use scrypt::scrypt as scrypt_kdf;
use scrypt::Params;
use serde::{Deserialize, Serialize};

/// Default output length in bytes for raw scrypt hashes.
pub const DEFAULT_OUTPUT_LEN: usize = 64;

/// OWASP-2025 minimum: `log_n = 17 (N = 131 072)`, `r = 8`, `p = 1`,
/// `dkLen = 64`.
pub fn owasp_minimum_2025() -> ScryptParams {
    ScryptParams {
        log_n: 17,
        r: 8,
        p: 1,
        dk_len: DEFAULT_OUTPUT_LEN,
    }
}

/// Scrypt parameters with explicit field names.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScryptParams {
    /// `log2(N)` — the CPU/memory cost factor exponent. OWASP-2025 ≥ 17.
    pub log_n: u8,
    /// Block size factor. OWASP-2025 default: 8.
    pub r: u32,
    /// Parallelisation factor. OWASP-2025 default: 1.
    pub p: u32,
    /// Derived-key length in bytes. Default: 64.
    pub dk_len: usize,
}

impl Default for ScryptParams {
    fn default() -> Self {
        owasp_minimum_2025()
    }
}

impl ScryptParams {
    /// Converts to the underlying `scrypt::Params`, surfacing parameter
    /// validation errors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidParameter`] if `log_n`, `r`, `p`, or
    /// `dk_len` violates scrypt's constraints (e.g. `log_n` outside
    /// `1..64`, or `r * p > 1 << 30`).
    pub fn to_native(self) -> Result<Params> {
        Params::new(self.log_n, self.r, self.p, self.dk_len)
            .map_err(|e| Error::InvalidParameter(e.to_string().into()))
    }
}

/// Marker type for the Scrypt hashing algorithm.
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
pub struct Scrypt;

impl HashingAlgorithm for Scrypt {
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        Self::hash_with(password, salt, ScryptParams::default())
    }
}

impl Scrypt {
    /// Hashes `password` with explicit [`ScryptParams`].
    pub fn hash_with(
        password: &str,
        salt: &str,
        params: ScryptParams,
    ) -> Result<Vec<u8>> {
        let native = params.to_native()?;
        let mut output = vec![0u8; params.dk_len];
        scrypt_kdf(
            password.as_bytes(),
            salt.as_bytes(),
            &native,
            &mut output,
        )
        .map_err(|e| {
            Error::hashing(
                crate::error::HashingErrorKind::Scrypt,
                e.to_string(),
            )
        })?;
        Ok(output)
    }
}
