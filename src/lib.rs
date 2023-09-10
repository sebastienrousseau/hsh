// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Quantum-Resistant Cryptographic Hash Library for Password Encryption and Verification
//!
//! Part of the [Mini Functions][0] family of libraries.
//!
//! ![Hash (HSH) Banner][banner]
//!
//! [![Crates.io][crate-shield]](https://crates.io/crates/hsh)
//! [![GitHub][github-shield]](https://github.com/sebastienrousseau/hsh)
//! [![Lib.rs][lib-rs-shield]](https://lib.rs/hsh)
//! [![License][license-shield]](http://opensource.org/licenses/MIT)
//! [![Rust][rust-shield]](https://www.rust-lang.org)
//!
//! ## Overview
//!
//! The `Hash (HSH)` library in Rust offers a secure interface for hash and digest algorithms, focusing on password encryption and verification. Utilizing state-of-the-art quantum-resistant cryptography, it provides robust security against current and future computational threats.
//!
//! ### Supported Password Hashing Schemes
//!
//! - **Argon2i**: Highly secure, resistant to both brute-force and rainbow table attacks. (Recommended)
//! - **Bcrypt**: Resistant to time-memory trade-off (TMTO) and brute-force attacks.
//! - **Scrypt**: Secure against both brute-force and rainbow table attacks.
//!
//! ## Features
//!
//! - **Versatility**: Supports multiple Password Hashing Schemes like Argon2i, Bcrypt, and Scrypt.
//! - **Future-Proof**: Quantum-resistant cryptography to secure against future technological advancements.
//! - **Ease of Use**: Simple API for storing and verifying hashed passwords.
//! - **Integrable**: Written in Rust, the library is fast, efficient, and easily integrable into other Rust projects.
//!
//! ## Core Components
//!
//! ### `Hash` Struct
//!
//! Contains:
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
#![deny(dead_code)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(unreachable_pub)]
#![doc(
    html_favicon_url = "https://kura.pro/hsh/images/favicon.ico",
    html_logo_url = "https://kura.pro/hsh/images/logos/hsh.svg",
    html_root_url = "https://docs.rs/hsh"
)]
#![crate_name = "hsh"]
#![crate_type = "lib"]


/// The `algorithms` module contains the password hashing algorithms.
pub mod algorithms;

/// The `macros` module contains functions for generating macros.
pub mod macros;

/// The `models` module contains the data models for the library.
pub mod models;

extern crate argon2rs;
extern crate base64;
extern crate bcrypt;
extern crate scrypt;
extern crate vrd;

use algorithms::{argon2i::Argon2i, bcrypt::Bcrypt, scrypt::Scrypt};
use argon2rs::argon2i_simple;
use base64::{engine::general_purpose, Engine as _};
use models::{hash::*, hash_algorithm::*};
use scrypt::scrypt;
use std::{fmt, str::FromStr};
use vrd::Random;

impl Hash {
    /// Creates a new `Hash` instance using Argon2i algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::{Hash, Salt};
    ///
    /// let password = "my_password";
    /// let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let result = Hash::new_argon2i(password, salt);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Argon2i hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_argon2i(password: &str, salt: Salt) -> Result<Self, String> {
        // Convert the Vec<u8> salt to a &str
        let salt_str = std::str::from_utf8(&salt)
            .map_err(|_| "Failed to convert salt to string")?;

        // Perform Argon2i hashing
        let calculated_hash = argon2i_simple(password, salt_str).to_vec();

        HashBuilder::new()
            .hash(calculated_hash)
            .salt(salt)
            .algorithm(HashAlgorithm::Argon2i)
            .build()
    }

    /// Creates a new `Hash` instance using Bcrypt algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::Hash;
    ///
    /// let password = "my_password";
    /// let cost: u32 = 16;
    ///
    /// let result = Hash::new_bcrypt(password, cost);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Bcrypt hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_bcrypt(password: &str, cost: u32) -> Result<Self, String> {
        // Perform Bcrypt hashing
        let hashed_password = bcrypt::hash(password, cost)
            .map_err(|e| format!("Failed to hash password with Bcrypt: {}", e))?;

        // In Bcrypt, the salt is embedded in the hashed password.
        // So, you can just use an empty salt when building the Hash object.
        let empty_salt = Vec::new();

        HashBuilder::new()
            .hash(hashed_password.as_bytes().to_vec())
            .salt(empty_salt)
            .algorithm(HashAlgorithm::Bcrypt)
            .build()
    }

    /// Creates a new `Hash` instance using Scrypt algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::{Hash, Salt};
    ///
    /// let password = "my_password";
    /// let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let result = Hash::new_scrypt(password, salt);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Scrypt hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_scrypt(password: &str, salt: Salt) -> Result<Self, String> {
        // Convert the Vec<u8> salt to a &str for hashing
        let salt_str = std::str::from_utf8(&salt)
            .map_err(|_| "Failed to convert salt to string")?;

        // Perform Scrypt hashing using a wrapper function that sets the parameters
        let calculated_hash = algorithms::scrypt::Scrypt::hash_password(password, salt_str)?;

        // Use the builder pattern to construct the Hash instance
        HashBuilder::new()
            .hash(calculated_hash)
            .salt(salt)
            .algorithm(HashAlgorithm::Scrypt)
            .build()
    }

    /// A function that returns the hash algorithm used by the hash map.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// A function that creates a new hash object from a hash value and a hash algorithm.
    pub fn from_hash(hash: &[u8], algo: &str) -> Result<Self, String> {
        let algorithm = match algo {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }?;

        Ok(Hash {
            salt: Vec::new(),
            hash: hash.to_vec(),
            algorithm,
        })
    }

    /// A function that creates a new hash object from a hash string in the format algorithm$salt$hash.
    pub fn from_string(hash_str: &str) -> Result<Self, String> {
        // Split the hash string into six parts, using the `$` character as the delimiter.
        let parts: Vec<&str> = hash_str.split('$').collect();

        // If the hash string does not contain six parts, return an error.
        if parts.len() != 6 {
            return Err(String::from("Invalid hash string"));
        }

        // Parse the algorithm from the first part of the hash string.
        let algorithm = Self::parse_algorithm(hash_str)?;

        // Parse the salt from the second, third, fourth, and fifth parts of the hash string.
        let salt = format!(
            "${}${}${}${}",
            parts[1], parts[2], parts[3], parts[4]
        );

        // Decode the hash bytes from the sixth part of the hash string.
        let hash_bytes =
            general_purpose::STANDARD.decode(parts[5]).map_err(
                |_| format!("Failed to decode base64: {}", parts[5]),
            )?;

        // Create the `Hash` object and return it.
        Ok(Hash {
            salt: salt.into_bytes(),
            hash: hash_bytes,
            algorithm,
        })
    }

    /// A function that generates a hash value for a password using the specified hash algorithm.
    /// The function takes three arguments:
    ///
    /// - password: The password to be hashed.
    /// - salt: A random string used to make the hash value unique.
    /// - algo: The name of the hash algorithm to use.
    ///
    /// The function returns a `Result` object containing the hash value if successful, or an error message if unsuccessful.
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Vec<u8>, String> {
        match algo {
            "argon2i" => Argon2i::hash_password(password, salt),
            "bcrypt" => Bcrypt::hash_password(password, salt),
            "scrypt" => Scrypt::hash_password(password, salt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }
    }

    /// A function that generates a random string of the specified length.
    pub fn generate_random_string(len: usize) -> String {
        let mut rng = Random::default();
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        (0..len)
            .map(|_| {
                chars
                    .chars()
                    .nth(rng.random_range(0, chars.len() as u32)
                        as usize)
                    .unwrap()
            })
            .collect()
    }

    /// A function that generates a random salt for a password using the specified hash algorithm.
    pub fn generate_salt(algo: &str) -> Result<String, String> {
        let mut rng = Random::default();
        match algo {
            "argon2i" => Ok(Self::generate_random_string(16)),
            "bcrypt" => {
                let salt: Vec<u8> = rng.bytes(16);
                let salt_array: [u8; 16] =
                    salt.try_into().map_err(|_| {
                        "Error: failed to convert salt to an array"
                    })?;
                Ok(general_purpose::STANDARD.encode(&salt_array[..]))
            }
            "scrypt" => {
                let salt: Vec<u8> = rng.bytes(32);
                let salt_array: [u8; 32] =
                    salt.try_into().map_err(|_| {
                        "Error: failed to convert salt to an array"
                    })?;
                Ok(general_purpose::STANDARD.encode(&salt_array[..]))
            }
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }
    }

    /// A function that returns the hash value of a hash object.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// A function that returns the length of the hash value of a hash object.
    pub fn hash_length(&self) -> usize {
        self.hash.len()
    }

    /// A function that creates a new hash object from a password, salt, and hash algorithm.
    pub fn new(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Self, String> {
        // Enforce a minimum password length of 8 characters.
        if password.len() < 8 {
            return Err(String::from("Password is too short. It must be at least 8 characters."));
        }
        let hash = Self::generate_hash(password, salt, algo)?;

        let algorithm = match algo {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }?;

        Ok(Self {
            hash,
            salt: salt.as_bytes().to_vec(),
            algorithm,
        })
    }

    /// A function that parses a JSON string into a hash object.
    pub fn parse(
        input: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let hash: Hash = serde_json::from_str(input)?;
        Ok(hash)
    }

    /// A function that parses a hash string into a hash algorithm.
    pub fn parse_algorithm(
        hash_str: &str,
    ) -> Result<HashAlgorithm, String> {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 2 {
            return Err(String::from("Invalid hash string"));
        }
        match parts[1] {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => {
                Err(format!("Unsupported hash algorithm: {}", parts[1]))
            }
        }
    }

    /// A function that returns the salt used to hash a password.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// A function that sets the hash value of a hash object.
    pub fn set_hash(&mut self, hash: &[u8]) {
        self.hash = hash.to_vec();
    }

    /// A function that sets the password of a hash object.
    pub fn set_password(
        &mut self,
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<(), String> {
        self.hash = Self::generate_hash(password, salt, algo)?;
        Ok(())
    }

    /// A function that sets the salt of a hash object.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }

    /// A function that converts a hash object to a string representation.
    pub fn to_string_representation(&self) -> String {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");

        format!("{}:{}", String::from_utf8_lossy(&self.salt), hash_str)
    }

    /// A function that verifies a password against a hash object.
    pub fn verify(&self, password: &str) -> Result<bool, &'static str> {
        let salt = std::str::from_utf8(&self.salt)
            .map_err(|_| "Failed to convert salt to string")?;

        match self.algorithm {
            HashAlgorithm::Argon2i => {
                // Hash the password once
                let calculated_hash = argon2i_simple(password, salt).to_vec();

                // Debugging information
                println!("Algorithm: Argon2i");
                println!("Provided password for verification: {}", password);
                println!("Salt used for verification: {}", salt);
                println!("Calculated Hash: {:?}", calculated_hash);
                println!("Stored Hash: {:?}", self.hash);

                // Perform the verification
                Ok(calculated_hash == self.hash)
            }
            HashAlgorithm::Bcrypt => {
                // Debugging information
                println!("Algorithm: Bcrypt");
                println!("Provided password for verification: {}", password);

                let hash_str = std::str::from_utf8(&self.hash)
                    .map_err(|_| "Failed to convert hash to string")?;
                bcrypt::verify(password, hash_str)
                    .map_err(|_| "Failed to verify Bcrypt password")
            }
            HashAlgorithm::Scrypt => {
                // Debugging information
                println!("Algorithm: Scrypt");
                println!("Provided password for verification: {}", password);
                println!("Salt used for verification: {}", salt);

                let scrypt_params = scrypt::Params::new(14, 8, 1, 64)
                    .map_err(|_| "Failed to create Scrypt params")?;
                let mut output = [0u8; 64];
                match scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                ) {
                    Ok(_) => {
                        println!("Calculated Hash: {:?}", output.to_vec());
                        println!("Stored Hash: {:?}", self.hash);
                        Ok(output.to_vec() == self.hash)
                    }
                    Err(_) => Err("Scrypt hashing failed"),
                }
            }
        }
    }

}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash {{ hash: {:?} }}", self.hash)
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for HashAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let algorithm = match s {
            "argon2i" => HashAlgorithm::Argon2i,
            "bcrypt" => HashAlgorithm::Bcrypt,
            "scrypt" => HashAlgorithm::Scrypt,
            _ => return Err(String::from("Invalid hash algorithm")),
        };
        Ok(algorithm)
    }
}

/// This is the main entry point for the `Hash (HSH)` library.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("HSH_TEST_MODE").unwrap_or_default() == "1" {
        return Err("Simulated error".into());
    }
    let name = "hsh";
    println!("Welcome to `{}` 👋!", { name }.to_uppercase());
    println!(
        "Quantum-Resistant Cryptographic Hash Library for Password Encryption and Verification."
    );
    Ok(())
}
