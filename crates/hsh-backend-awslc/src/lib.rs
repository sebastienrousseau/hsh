// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! FIPS 140-3 routing layer for the [`hsh`] password-hashing crate.
//!
//! This crate exists so that callers who need a **FIPS 140-3 validated**
//! deployment can route `hsh`'s PBKDF2-HMAC-SHA-256 / SHA-512 derivation
//! through [AWS-LC FIPS 3.0](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4759)
//! (CMVP Cert #4759) — the only currently-validated implementation of a
//! password-suitable KDF anywhere in the Rust ecosystem.
//!
//! The crate intentionally exposes a **minimal surface**: one function,
//! [`pbkdf2_derive`], that mirrors the contract of `hsh`'s pure-Rust
//! PBKDF2 path. Argon2id, bcrypt, and scrypt are deliberately **not**
//! re-exported because no CMVP-validated implementation exists for any
//! of them; see [`doc/FIPS.md`](../../doc/FIPS.md) and
//! [`doc/adr/0004-fips-strategy.md`](../../doc/adr/0004-fips-strategy.md)
//! for the reasoning.
//!
//! ## Build requirements
//!
//! Pulling this crate in transitively builds the AWS-LC FIPS sub-module,
//! which requires the following on the **build host** (not on the
//! runtime host):
//!
//! - Go ≥ 1.21
//! - CMake ≥ 3.18
//! - A recent clang (Xcode CLT on macOS, `clang` ≥ 14 on Linux)
//!
//! These prerequisites are why `hsh` ships this routing crate as an
//! **optional** dependency behind the `fips` feature flag rather than as
//! a default. See the deployment matrix in `doc/FIPS.md`.
//!
//! ## Usage
//!
//! Callers should depend on `hsh` with the `fips` feature enabled —
//! `hsh` re-routes PBKDF2 through this crate automatically. Direct use
//! of [`pbkdf2_derive`] is supported but not the primary entry point.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

use aws_lc_rs::pbkdf2;
use std::num::NonZeroU32;

/// PRF variant. The two SHA-2 variants below are validated under
/// AWS-LC FIPS 3.0 (CMVP Cert #4759).
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Prf {
    /// PBKDF2-HMAC-SHA-256.
    Sha256,
    /// PBKDF2-HMAC-SHA-512.
    Sha512,
}

/// Error returned by [`pbkdf2_derive`] for invalid parameters. All
/// errors are caller-side: AWS-LC itself does not surface
/// recoverable failures from the derive path.
#[derive(Debug)]
pub enum DeriveError {
    /// `iterations` was zero. PBKDF2 requires `iterations >= 1`.
    IterationsZero,
    /// `dk_len` was zero. The derived key must have at least 1 byte.
    DkLenZero,
}

impl core::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::IterationsZero => f.write_str(
                "PBKDF2 iterations must be >= 1 (got 0)",
            ),
            Self::DkLenZero => f.write_str(
                "PBKDF2 dk_len must be > 0 (got 0)",
            ),
        }
    }
}

impl std::error::Error for DeriveError {}

/// Derives `dk_len` bytes from `password` and `salt` using
/// PBKDF2-HMAC-{SHA-256, SHA-512} as routed through AWS-LC FIPS 3.0.
///
/// # Errors
///
/// Returns [`DeriveError::IterationsZero`] if `iterations == 0` and
/// [`DeriveError::DkLenZero`] if `dk_len == 0`. AWS-LC's
/// [`pbkdf2::derive`] itself does not surface recoverable errors.
///
/// # Examples
///
/// ```no_run
/// use hsh_backend_awslc::{pbkdf2_derive, Prf};
///
/// let out = pbkdf2_derive(
///     b"correct horse battery staple",
///     b"salt-which-must-be-per-password-random",
///     Prf::Sha256,
///     600_000,
///     32,
/// ).unwrap();
/// assert_eq!(out.len(), 32);
/// ```
pub fn pbkdf2_derive(
    password: &[u8],
    salt: &[u8],
    prf: Prf,
    iterations: u32,
    dk_len: usize,
) -> Result<Vec<u8>, DeriveError> {
    let iters = NonZeroU32::new(iterations)
        .ok_or(DeriveError::IterationsZero)?;
    if dk_len == 0 {
        return Err(DeriveError::DkLenZero);
    }
    let algorithm = match prf {
        Prf::Sha256 => pbkdf2::PBKDF2_HMAC_SHA256,
        Prf::Sha512 => pbkdf2::PBKDF2_HMAC_SHA512,
    };
    let mut out = vec![0u8; dk_len];
    pbkdf2::derive(algorithm, iters, salt, password, &mut out);
    Ok(out)
}

/// Returns `true` to confirm that this crate is wired into the build.
/// Used by `hsh::backend::Backend::fips_available_in_build` to flip
/// the FIPS-availability flag without a load-bearing magic constant.
#[must_use]
pub const fn fips_routing_compiled_in() -> bool {
    true
}
