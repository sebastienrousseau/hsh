// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Backend selector — declares whether the [`crate::Policy`] requires
//! FIPS 140-3 validated crypto.
//!
//! `Backend` is a *requirement* the caller declares; whether it can be
//! satisfied depends on the build configuration:
//!
//! - [`Backend::Native`] — any KDF works; primitives come from the
//!   pure-Rust RustCrypto stack. **Default.**
//! - [`Backend::Fips140Required`] — only KDFs with a FIPS 140-3
//!   validated implementation are allowed. Today that means
//!   **PBKDF2-HMAC-SHA-256/512** routed through `aws-lc-rs`
//!   (`fips` feature). Argon2 / bcrypt / scrypt have **no** FIPS
//!   module anywhere — minting them with `Fips140Required` is a
//!   compile-time-undetectable error that [`crate::api::hash`] will
//!   refuse at runtime.
//!
//! See `doc/FIPS.md` and `doc/adr/0004-fips-strategy.md` for the full strategy.

use serde::{Deserialize, Serialize};

/// Crypto-validation requirement declared by a [`crate::Policy`].
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
pub enum Backend {
    /// Use the pure-Rust RustCrypto primitives. No FIPS claim.
    #[default]
    Native,
    /// Only allow primitives whose underlying implementation is
    /// FIPS 140-3 validated. Requires the `fips` Cargo feature.
    Fips140Required,
}

impl Backend {
    /// Returns `true` when the backend demands FIPS-validated crypto.
    #[must_use]
    pub const fn is_fips(self) -> bool {
        matches!(self, Self::Fips140Required)
    }

    /// Returns `true` if this build can actually satisfy a FIPS
    /// requirement. True when the `fips` Cargo feature is enabled,
    /// which pulls in the `hsh-backend-awslc` companion crate and
    /// routes PBKDF2 through AWS-LC FIPS 3.0 (CMVP Cert #4759).
    /// False otherwise — [`crate::api::hash`] will refuse to mint a
    /// FIPS-tagged hash when this returns false. See ADR-0004 +
    /// `doc/FIPS.md`.
    #[must_use]
    pub const fn fips_available_in_build() -> bool {
        cfg!(feature = "fips")
    }
}
