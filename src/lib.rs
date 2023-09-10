// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # HSH: Quantum-Resistant Cryptographic Hash Library for Robust Password Encryption & Verification
//!
//! A highly secure cryptographic hash library with a focus on password encryption and verification. Designed with quantum-resistant cryptography, this library provides a robust line of defence against current and emerging computational threats.
//!
//! ![Hash (HSH) Banner][banner]
//!
//! Part of the [Mini Functions][0] family of libraries.
//!
//! [![Available on Crates.io][crate-shield]](https://crates.io/crates/hsh)
//! [![GitHub Repository][github-shield]](https://github.com/sebastienrousseau/hsh)
//! [![Available on Lib.rs][lib-rs-shield]](https://lib.rs/hsh)
//! [![MIT License][license-shield]](http://opensource.org/licenses/MIT)
//! [![Built with Rust][rust-shield]](https://www.rust-lang.org)
//!
//! ## Overview
//!
//! The Hash (HSH) library is a secure and easy-to-use library for password encryption and verification in Rust. It supports multiple password hashing schemes, including Argon2i, Bcrypt, and Scrypt. It is specifically designed for password encryption and verification, and uses state-of-the-art quantum-resistant cryptography to ensure maximum security against both current and future computational threats.
//!
//! ### Supported Password Hashing Schemes
//!
//! - **Argon2i**: Highly secure, resistant to both brute-force and rainbow table attacks. (Recommended)
//! - **Bcrypt**: Resistant to time-memory trade-off (TMTO) and brute-force attacks.
//! - **Scrypt**: Secure against both brute-force and rainbow table attacks.
//!
//! ## Features
//!
//! - **Ease of Use**: Simple API for storing and verifying hashed passwords.
//! - **Future-Proof**: Quantum-resistant cryptography to secure against future technological advancements.
//! - **Integrable**: Written in Rust, the library is fast, efficient, and easily integrable into other Rust projects.
//! - **Versatility**: Supports multiple Password Hashing Schemes like Argon2i, Bcrypt, and Scrypt.
//!
//! ## Core Components
//!
//! ### `Hash` Struct
//!
//! Contains:
//!
//! - **algorithm**: Enum representing the hashing algorithm (Argon2i, Bcrypt, Scrypt).
//! - **hash**: Byte vector containing the hashed password.
//! - **salt**: Byte vector containing the salt used in hashing.
//!
//! ### `HashAlgorithm` Enum
//!
//! Provides variants for supported hashing algorithms: Argon2i, Bcrypt, and Scrypt.
//!
//! ## Methods
//!
//! The `Hash` struct offers methods for password hashing and management, including but not limited to:
//!
//! - Creating new Hash objects.
//! - Generating and setting salts and hashes.
//! - Verifying passwords against stored hashes.
//!
//! ## Getting Started
//!
//! Add `Hash (HSH)` as a dependency in your `Cargo.toml` and import it in your main Rust file.
//!
//! ### Example
//!
//! Here's a simple example demonstrating basic usage:
//!
//! ```rust
//! use hsh::models::hash::Hash;  // Import the Hash struct
//!
//! fn main() {
//!     let password = "password123";
//!     let salt = "somesalt";
//!     let algo = "argon2i";
//!
//!     let original_hash = Hash::new(password, salt, algo).expect("Failed to create hash");
//!     let hashed_password = original_hash.hash.clone();
//!
//!     assert_eq!(original_hash.hash(), &hashed_password);
//! }
//! ```
//!
//! ## License
//!
//! Licensed under the MIT and Apache License (Version 2.0).
//!
//! [banner]: https://kura.pro/hsh/images/banners/banner-hsh.svg
//! [crate-shield]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006
//! [github-shield]: https://img.shields.io/badge/github-555555?style=for-the-badge&labelColor=000000&logo=github
//! [lib-rs-shield]: https://img.shields.io/badge/lib.rs-v0.0.5-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4
//! [license-shield]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B
//! [rust-shield]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust
//!
//! [0]: https://minifunctions.com/
//! [1]: http://www.apache.org/licenses/LICENSE-2.0
//! [2]: http://opensource.org/licenses/MIT

#![cfg_attr(feature = "bench", feature(test))]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![doc(
    html_favicon_url = "https://kura.pro/hsh/images/favicon.ico",
    html_logo_url = "https://kura.pro/hsh/images/logos/hsh.svg",
    html_root_url = "https://docs.rs/hsh"
)]
#![crate_name = "hsh"]
#![crate_type = "lib"]

/// The `algorithms` module contains the password hashing algorithms.
pub mod algorithms;

/// The `loggers` module contains the loggers for the library.
pub mod loggers;

/// The `macros` module contains functions for generating macros.
pub mod macros;

/// The `models` module contains the data models for the library.
pub mod models;

/// This is the main entry point for the `Hash (HSH)` library.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HSH_TEST_MODE").unwrap_or_default() == "1" {
        return Err("Simulated error".into());
    }

    let name = "hsh";
    println!("Welcome to `{}` 👋!", name.to_uppercase());
    println!(
        "Quantum-Resistant Cryptographic Hash Library for Password Encryption and Verification."
    );
    Ok(())
}
