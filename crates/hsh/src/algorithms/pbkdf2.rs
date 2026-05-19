// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PBKDF2-HMAC-SHA-256 / SHA-512 wrapper.
//!
//! PBKDF2 is the only password-hashing KDF that has a FIPS 140-3
//! validated implementation today (via `aws-lc-rs`). It is the right
//! choice when compliance dictates and Argon2id is unavailable.
//!
//! ## Routing
//!
//! - **Today (v0.0.9)**: pure-Rust RustCrypto `pbkdf2` regardless of
//!   the `fips` feature. The feature is a forward-compat marker — see
//!   ADR-0004 and `doc/FIPS.md`.
//! - **Phase 4 follow-up**: the planned `hsh-backend-awslc` crate
//!   routes PBKDF2 derive through `aws-lc-rs`'s FIPS 140-3 Level 1
//!   validated module. Public API stays unchanged.

use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use serde::{Deserialize, Serialize};

/// Default derived-key length in bytes.
pub const DEFAULT_OUTPUT_LEN: usize = 32;

/// Hash function variant used by PBKDF2.
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
pub enum Prf {
    /// PBKDF2-HMAC-SHA-256 (FIPS-validated via `aws-lc-rs`).
    #[default]
    Sha256,
    /// PBKDF2-HMAC-SHA-512 (FIPS-validated via `aws-lc-rs`).
    Sha512,
}

impl Prf {
    /// Returns the PHC algorithm identifier (`"pbkdf2-sha256"` etc.).
    #[must_use]
    pub const fn phc_id(self) -> &'static str {
        match self {
            Self::Sha256 => "pbkdf2-sha256",
            Self::Sha512 => "pbkdf2-sha512",
        }
    }
}

/// PBKDF2 parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Pbkdf2Params {
    /// PRF (HMAC-SHA-256 by default — the FIPS-validated path).
    pub prf: Prf,
    /// Iteration count. **OWASP-2025** minimums:
    /// - SHA-256: **600 000**
    /// - SHA-512: **210 000**
    pub iterations: u32,
    /// Derived-key length in bytes. Default: 32.
    pub dk_len: usize,
}

impl Default for Pbkdf2Params {
    fn default() -> Self {
        Self::owasp_minimum_2025()
    }
}

impl Pbkdf2Params {
    /// OWASP Password Storage Cheat Sheet 2025 minimum for
    /// PBKDF2-HMAC-SHA-256: `iterations = 600_000`, `dk_len = 32`.
    #[must_use]
    pub const fn owasp_minimum_2025() -> Self {
        Self {
            prf: Prf::Sha256,
            iterations: 600_000,
            dk_len: DEFAULT_OUTPUT_LEN,
        }
    }

    /// OWASP-2025 minimum for the SHA-512 PRF: `iterations = 210_000`,
    /// `dk_len = 32`.
    #[must_use]
    pub const fn owasp_minimum_2025_sha512() -> Self {
        Self {
            prf: Prf::Sha512,
            iterations: 210_000,
            dk_len: DEFAULT_OUTPUT_LEN,
        }
    }
}

/// Marker type for the PBKDF2 hashing algorithm.
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
pub struct Pbkdf2;

impl HashingAlgorithm for Pbkdf2 {
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>> {
        Self::hash_with(password, salt, Pbkdf2Params::default())
    }
}

impl Pbkdf2 {
    /// Derives `dk_len` bytes from `password` and `salt` under the
    /// supplied [`Pbkdf2Params`].
    pub fn hash_with(
        password: &str,
        salt: &str,
        params: Pbkdf2Params,
    ) -> Result<Vec<u8>> {
        if params.iterations < 1 {
            return Err(Error::InvalidParameter(
                "iterations must be >= 1".into(),
            ));
        }
        if params.dk_len == 0 {
            return Err(Error::InvalidParameter(
                "dk_len must be > 0".into(),
            ));
        }

        // The `fips` feature is currently a marker only — see
        // doc/FIPS.md and ADR-0004. Once the dedicated
        // `hsh-backend-awslc` crate lands, this branch will route
        // through the FIPS-validated module without changing the
        // public API.
        rust_crypto::derive(password, salt, params)
    }
}

mod rust_crypto {
    //! Pure-Rust PBKDF2 derive via the RustCrypto `pbkdf2` crate.

    use super::{Pbkdf2Params, Prf};
    use crate::error::{Error, Result};
    use hmac::Hmac;
    use sha2::{Sha256, Sha512};

    pub(super) fn derive(
        password: &str,
        salt: &str,
        params: Pbkdf2Params,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; params.dk_len];
        match params.prf {
            Prf::Sha256 => pbkdf2::pbkdf2::<Hmac<Sha256>>(
                password.as_bytes(),
                salt.as_bytes(),
                params.iterations,
                &mut out,
            )
            .map_err(|e| Error::Hashing(e.to_string()))?,
            Prf::Sha512 => pbkdf2::pbkdf2::<Hmac<Sha512>>(
                password.as_bytes(),
                salt.as_bytes(),
                params.iterations,
                &mut out,
            )
            .map_err(|e| Error::Hashing(e.to_string()))?,
        }
        Ok(out)
    }
}
