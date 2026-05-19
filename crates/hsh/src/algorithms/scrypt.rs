// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Scrypt wrapper.
//!
//! **Roadmap note**: parameters are hard-coded to `log_n=14, r=8, p=1, dkLen=64`
//! — below the OWASP-2025 minimum of `log_n=17`. Phase 1 (issue #157) makes
//! these configurable via `Policy`.

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use scrypt::scrypt;
use scrypt::Params;
use serde::{Deserialize, Serialize};

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
    /// Hashes a plaintext `password` with scrypt at fixed parameters
    /// `log_n=14, r=8, p=1, dkLen=64`.
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        let params = Params::new(14, 8, 1, 64)
            .map_err(|e| Error::InvalidParameter(e.to_string()))?;
        let mut output = [0u8; 64];
        scrypt(
            password.as_bytes(),
            salt.as_bytes(),
            &params,
            &mut output,
        )
        .map_err(|e| Error::Hashing(e.to_string()))?;
        Ok(output.to_vec())
    }
}
