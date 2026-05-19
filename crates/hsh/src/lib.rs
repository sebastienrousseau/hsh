#![forbid(unsafe_code)]
#![cfg_attr(
    test,
    allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Hash (HSH) — Enterprise password hashing for Rust
//!
//! Modern, multi-algorithm password hashing with constant-time verification,
//! zeroized secrets, and a roadmap to PHC compliance, KMS-backed peppers,
//! and an optional FIPS 140-3 backend via `aws-lc-rs`.
//!
//! [![Available on Crates.io][crate-shield]](https://crates.io/crates/hsh)
//! [![GitHub Repository][github-shield]](https://github.com/sebastienrousseau/hsh)
//! [![Available on Lib.rs][lib-rs-shield]](https://lib.rs/hsh)
//! [![MIT License][license-shield]](http://opensource.org/licenses/MIT)
//! [![Built with Rust][rust-shield]](https://www.rust-lang.org)
//!
//! ## What HSH is
//!
//! - A safe, well-lit interface over the [`argon2`](https://crates.io/crates/argon2),
//!   [`bcrypt`](https://crates.io/crates/bcrypt), and
//!   [`scrypt`](https://crates.io/crates/scrypt) crates.
//! - Constant-time hash comparison via
//!   [`subtle`](https://crates.io/crates/subtle), and
//!   [`zeroize`](https://crates.io/crates/zeroize) on secret material.
//! - A structured [`Error`](crate::error::Error) type that implements
//!   [`std::error::Error`] for clean `?` interop.
//!
//! ## What HSH is **not**
//!
//! - **Not post-quantum cryptography.** Memory-hard KDFs like Argon2id make
//!   brute-force expensive on both classical and quantum hardware (Grover
//!   gives only a √-speedup), but they are *not* PQ primitives. If you need
//!   ML-KEM, ML-DSA, or SLH-DSA, use the
//!   [`pqcrypto`](https://crates.io/crates/pqcrypto) family or
//!   [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).
//! - **Not yet PHC-compliant** in the serialized hash form — see Phase 1
//!   (issue #159) on the roadmap.
//! - **Not yet FIPS-validated** — see Phase 4 (issue #143).
//!
//! ## Algorithms supported today (v0.0.9)
//!
//! | Variant   | Status        | Notes                                         |
//! | --------- | ------------- | --------------------------------------------- |
//! | Argon2i   | Default       | Phase 1 replaces with Argon2id (#156)         |
//! | Bcrypt    | Supported     | 72-byte safety rail lands in Phase 1 (#158)   |
//! | Scrypt    | Supported     | Hard-coded params; configurable in Phase 1    |
//!
//! ## Quick example
//!
//! ```
//! use hsh::models::hash::Hash;
//!
//! let password = "correct horse battery staple";
//! let salt     = "abcdefghijklmnop";
//! let h = Hash::new(password, salt, "argon2i").unwrap();
//! assert!(h.verify(password).unwrap());
//! assert!(!h.verify("wrong password").unwrap());
//! ```
//!
//! ## License
//!
//! Licensed under either of MIT (LICENSE-MIT) or Apache-2.0 (LICENSE-APACHE),
//! at your option.
//!
//! [crate-shield]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006
//! [github-shield]: https://img.shields.io/badge/github-555555?style=for-the-badge&labelColor=000000&logo=github
//! [lib-rs-shield]: https://img.shields.io/badge/lib.rs-v0.0.9-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4
//! [license-shield]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B
//! [rust-shield]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust

#![doc(
    html_favicon_url = "https://kura.pro/hsh/images/favicon.ico",
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
pub fn run() -> Result<()> {
    if std::env::var("HSH_TEST_MODE").unwrap_or_default() == "1" {
        return Err(Error::Verification("simulated error".into()));
    }

    let name = "hsh";
    println!("Welcome to `{}` 👋!", name.to_uppercase());
    println!("Enterprise password hashing for Rust.");
    Ok(())
}
