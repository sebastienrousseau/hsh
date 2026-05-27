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
//! - **Default build** (no `fips` feature): pure-Rust RustCrypto
//!   `pbkdf2`. Sufficient for any caller that doesn't have a FIPS
//!   140-3 compliance requirement.
//! - **`fips` feature enabled**: derivations route through the
//!   `hsh-backend-awslc` companion crate, which wraps `aws-lc-rs`
//!   PBKDF2 inside the AWS-LC FIPS 3.0 module (CMVP Cert #4759).
//!   Public API stays identical; only the underlying primitive
//!   provider changes. See ADR-0004 and `doc/FIPS.md`.

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
        Self::hash_with(
            password.as_bytes(),
            salt.as_bytes(),
            Pbkdf2Params::default(),
        )
    }
}

impl Pbkdf2 {
    /// Derives `dk_len` bytes from `password` and `salt` under the
    /// supplied [`Pbkdf2Params`]. Both inputs are accepted as raw byte
    /// slices — PBKDF2 doesn't impose a UTF-8 constraint.
    pub fn hash_with(
        password: &[u8],
        salt: &[u8],
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

        // When the `fips` feature is enabled, route through the
        // AWS-LC FIPS 3.0 module via the `hsh-backend-awslc` crate.
        // Otherwise fall back to the pure-Rust RustCrypto path. The
        // observable output is identical for the same inputs — both
        // paths implement RFC 8018 PBKDF2 — but only the FIPS route
        // satisfies CMVP-validated-module compliance requirements.
        #[cfg(feature = "fips")]
        {
            aws_lc::derive(password, salt, params)
        }
        #[cfg(not(feature = "fips"))]
        {
            rust_crypto::derive(password, salt, params)
        }
    }
}

#[cfg(feature = "fips")]
mod aws_lc {
    //! PBKDF2 derive via `hsh-backend-awslc` → `aws-lc-rs` → AWS-LC
    //! FIPS 3.0 module (CMVP Cert #4759).

    use super::{Pbkdf2Params, Prf};
    use crate::error::{Error, HashingErrorKind, Result};
    use hsh_backend_awslc::{pbkdf2_derive, Prf as AwslcPrf};

    pub(super) fn derive(
        password: &[u8],
        salt: &[u8],
        params: Pbkdf2Params,
    ) -> Result<Vec<u8>> {
        let prf = match params.prf {
            Prf::Sha256 => AwslcPrf::Sha256,
            Prf::Sha512 => AwslcPrf::Sha512,
        };
        pbkdf2_derive(
            password,
            salt,
            prf,
            params.iterations,
            params.dk_len,
        )
        .map_err(|e| {
            Error::hashing(HashingErrorKind::Pbkdf2, e.to_string())
        })
    }
}

// The pure-Rust module stays compiled even when the `fips` feature is
// on, so parity tests can compare both paths. The `allow(dead_code)`
// suppresses the workspace-level `dead_code = deny` lint when only the
// FIPS path is reachable from the dispatcher above.
#[allow(dead_code)]
mod rust_crypto {
    //! Pure-Rust PBKDF2 derive via the RustCrypto `pbkdf2` crate.

    use super::{Pbkdf2Params, Prf};
    use crate::error::{Error, HashingErrorKind, Result};
    use hmac::Hmac;
    use sha2::{Sha256, Sha512};

    pub(super) fn derive(
        password: &[u8],
        salt: &[u8],
        params: Pbkdf2Params,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; params.dk_len];
        match params.prf {
            Prf::Sha256 => pbkdf2::pbkdf2::<Hmac<Sha256>>(
                password,
                salt,
                params.iterations,
                &mut out,
            )
            .map_err(|e| {
                Error::hashing(HashingErrorKind::Pbkdf2, e.to_string())
            })?,
            Prf::Sha512 => pbkdf2::pbkdf2::<Hmac<Sha512>>(
                password,
                salt,
                params.iterations,
                &mut out,
            )
            .map_err(|e| {
                Error::hashing(HashingErrorKind::Pbkdf2, e.to_string())
            })?,
        }
        Ok(out)
    }
}
