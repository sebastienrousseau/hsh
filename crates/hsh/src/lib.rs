#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Hash (HSH) — multi-algorithm password hashing for Rust
//!
//! PHC-formatted hash storage with constant-time verification, KMS-backed
//! peppering, FIPS 140-3 fail-closed contract, and automatic rehash on
//! policy drift. Built on the RustCrypto stack with
//! `#![forbid(unsafe_code)]` workspace-wide.
//!
//! [![Crates.io][crate-shield]](https://crates.io/crates/hsh)
//! [![Docs.rs][docs-shield]](https://docs.rs/hsh)
//! [![Lib.rs][lib-rs-shield]](https://lib.rs/crates/hsh)
//! [![License][license-shield]](https://opensource.org/licenses/MIT)
//! [![Rust][rust-shield]](https://www.rust-lang.org)
//!
//! ## Quick start
//!
//! ```rust
//! use hsh::{Outcome, Policy, api};
//!
//! fn main() -> Result<(), hsh::Error> {
//!     let policy = Policy::owasp_minimum_2025();
//!     let stored = api::hash(&policy, "correct horse battery staple")?;
//!
//!     let outcome = api::verify_and_upgrade(
//!         &policy,
//!         "correct horse battery staple",
//!         &stored,
//!     )?;
//!
//!     assert!(outcome.is_valid());
//!     assert!(!outcome.needs_rehash());
//!     Ok(())
//! }
//! ```
//!
//! ## What `hsh` ships in v0.0.9
//!
//! | Algorithm | Status | OWASP-2025 default |
//! | --------- | ------ | ------------------ |
//! | **Argon2id** (default) | ✅ Recommended | `m = 19 456 KiB`, `t = 2`, `p = 1` |
//! | **Bcrypt** | ✅ Hardened — 72-byte safety rail (CVE-2025-22228) | `cost = 10` |
//! | **Scrypt** | ✅ Configurable | `N = 2^17`, `r = 8`, `p = 1` |
//! | **PBKDF2-HMAC-SHA-256/512** | ✅ FIPS-eligible | `iters = 600 000` / `210 000` |
//! | Argon2i / Argon2d | Verify-only (legacy) | — |
//!
//! The verifier accepts any of the four production algorithms above
//! interchangeably (plus the legacy Argon2 variants); the live
//! [`Policy`] only governs *new* hashes and rehash targets.
//!
//! ## What `hsh` is **not**
//!
//! - **Not post-quantum cryptography.** Memory-hard KDFs like Argon2id
//!   raise the cost of offline brute-force on both classical and
//!   quantum hardware (Grover yields only a √-speedup), but they are
//!   not PQ primitives. For ML-KEM, ML-DSA, or SLH-DSA, use
//!   [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).
//! - **Not a self-validating FIPS 140-3 module.** The crate carries a
//!   [`Backend::Fips140Required`] *contract* — [`api::hash`] refuses to
//!   mint hashes outside FIPS-routed primitives — but the underlying
//!   crypto today is the pure-Rust RustCrypto stack. The dedicated
//!   `hsh-backend-awslc` follow-up routes through the validated
//!   `aws-lc-rs` FIPS module without changing the public API. See
//!   [`doc/FIPS.md`][fips-doc] and [`doc/adr/0004-fips-strategy.md`][adr-fips].
//! - **Not a general-purpose digest library.** For SHA-2 / SHA-3 /
//!   BLAKE3 content addressing, use the companion
//!   [`hsh-digest`](https://crates.io/crates/hsh-digest) crate.
//!
//! ## Architecture
//!
//! - **Policy-driven**: a versioned [`Policy`] declares the primary
//!   algorithm and per-algorithm parameters. Construct via the
//!   [`Policy::owasp_minimum_2025`] / [`Policy::rfc9106_first_recommended`]
//!   / [`Policy::fips_140_pbkdf2`] presets or the [`policy::PolicyBuilder`].
//! - **Auto-rehash on drift**: [`api::verify_and_upgrade`] returns an
//!   [`Outcome`] whose `Valid` variant folds the new PHC string into
//!   `rehashed: Option<String>` — `Some(_)` precisely when the stored
//!   hash falls below current policy. The caller persists the new value
//!   on next login.
//! - **Optional peppering**: with the `pepper` feature, [`Policy::with_pepper`]
//!   attaches an HMAC-SHA-256 pepper provider with versioned key
//!   rotation. Hashes carry a `hsh-pepper:<version>:` wrapper; rotation
//!   is non-destructive.
//! - **Structured errors**: [`Error`] is a `#[non_exhaustive]`
//!   `thiserror` enum with `Clone + Send + Sync` and a typed
//!   [`error::HashingErrorKind`] discriminant for downcasting without
//!   parsing strings.
//!
//! ## Cargo features
//!
//! | Feature | Default | What it adds |
//! | ------- | ------- | ------------ |
//! | `pepper` | off | KMS-backed peppering via the `hsh-kms` companion crate |
//! | `fips` | off | Forward-compat marker for the `aws-lc-rs` FIPS backend |
//! | `compat-v0_0_x` | off | Re-exposes the pre-0.0.9 stringly-typed API for migration |
//!
//! ## License
//!
//! Dual-licensed under
//! [MIT](https://opensource.org/licenses/MIT) or
//! [Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0),
//! at your option.
//!
//! [crate-shield]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006
//! [docs-shield]: https://img.shields.io/badge/docs.rs-hsh-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//! [lib-rs-shield]: https://img.shields.io/badge/lib.rs-hsh-orange.svg?style=for-the-badge
//! [license-shield]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B
//! [rust-shield]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust
//! [fips-doc]: https://github.com/sebastienrousseau/hsh/blob/main/doc/FIPS.md
//! [adr-fips]: https://github.com/sebastienrousseau/hsh/blob/main/doc/adr/0004-fips-strategy.md

#![doc(
    html_favicon_url = "https://cloudcdn.pro/hsh/v1/logos/hsh.svg",
    html_logo_url = "https://cloudcdn.pro/hsh/v1/logos/hsh.svg",
    html_root_url = "https://docs.rs/hsh"
)]
#![crate_name = "hsh"]
#![crate_type = "lib"]

/// Password hashing algorithm wrappers.
pub mod algorithms;

/// High-level enterprise API — PHC-format hashing and
/// [`api::verify_and_upgrade`] with policy-driven rehash.
pub mod api;

/// Backend selector — declares whether the [`Policy`] requires FIPS
/// 140-3 validated crypto.
pub mod backend;

/// Structured error type for fallible operations.
pub mod error;

/// Core data models — [`models::hash::Hash`] and the
/// [`models::hash_algorithm::HashAlgorithm`] enum.
pub mod models;

/// Verification [`outcome::Outcome`] reported by [`api::verify_and_upgrade`].
pub mod outcome;

/// Versioned [`policy::Policy`] describing primary algorithm + params.
pub mod policy;

pub use backend::Backend;
pub use error::{Error, Result};
pub use outcome::Outcome;
pub use policy::{Policy, PrimaryAlgorithm};

/// Library entry point used by the `hsh` binary.
///
/// Prints a short welcome banner and returns `Ok(())`. Exists so the
/// `hsh-cli` binary has a single library-side entry to call into.
///
/// # Errors
///
/// Returns [`Error::Verification`] only when the `HSH_TEST_MODE`
/// environment variable is set to `"1"` — the integration test suite
/// uses this to exercise the error-propagation path.
pub fn run() -> Result<()> {
    if std::env::var("HSH_TEST_MODE").unwrap_or_default() == "1" {
        return Err(Error::Verification("simulated error".into()));
    }

    let name = "hsh";
    println!("Welcome to `{}` 👋!", name.to_uppercase());
    println!("Enterprise password hashing for Rust.");
    Ok(())
}
