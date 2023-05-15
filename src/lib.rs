// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Quantum-Resistant Cryptographic Hash Library for Password Hashing and Verification
//!
//! *Part of the [Mini Functions][0] family of libraries.*
//!
//! <center>
//!
//! ![Hash (HSH) Banner][banner]
//!
//! [![Crates.io][crate-shield]](<https://crates.io/crates/hsh>)
//! [![GitHub][github-shield]](<https://github.com/sebastienrousseau/hsh>)
//! [![Lib.rs][lib-rs-shield]](<https://lib.rs/hsh>)
//! [![License][license-shield]](<http://opensource.org/licenses/MIT>)
//! [![Rust][rust-shield]](<https://www.rust-lang.org>)
//!
//! </center>
//!
//! ## Overview 📖
//!
//! The Hash (HSH) library is a cryptographic hash library for
//! password hashing and verification in Rust, designed to provide
//! robust security for passwords, utilizing the latest advancements in
//! quantum-resistant cryptography.
//!
//! The library is designed to be easy to use, with a simple API that
//! allows for the generation, retrieval, and verification of password
//! hashes.
//!
//! It supports the following hash algorithms:
//!
//! - **Argon2i**: A memory-hard password hashing function designed to resist GPU-based attacks and secure against both brute-force attacks and rainbow table attacks.
//! - **Bcrypt**: A password hashing function designed to resist time-memory trade-off (TMTO) attacks, secure against brute-force attacks.
//! - **Scrypt**: A password hashing function designed to be secure against both brute-force attacks and rainbow table attacks.
//!
//! ## Features ✨
//!
//! ### Hash Struct
//!
//! The Hash struct has four fields:
//!
//! - **algorithm**: An enum that stores the algorithm used for password hashing. The enum has three variants: Argon2i, Bcrypt, and Scrypt.
//! - **hash**: A vector of bytes that stores the hashed password.
//! - **salt**: A vector of bytes that stores the salt used for password hashing.
//!
//! ### Hash Algorithms
//!
//! The HashAlgorithm enum has three variants:
//!
//! - **Argon2i**: The Argon2i algorithm
//! - **Bcrypt**: The Bcrypt algorithm.
//! - **Scrypt**: The Scrypt algorithm.
//!
//! ### Hash Methods
//!
//! The Hash struct provides the following methods for password
//! hashing and verification:
//!
//! - `algorithm`: A function that returns the hash algorithm used by the hash map.
//! - `from_hash`: A function that creates a new hash object from a hash value and a hash algorithm.
//! - `from_string`: A function that creates a new hash object from a hash string in the format algorithm$salt$hash.
//! - `generate_hash`: A function that generates a hash value for a password using the specified hash algorithm.
//! - `generate_random_string`: A function that generates a random string of the specified length.
//! - `generate_salt`: A function that generates a random salt for a password using the specified hash algorithm.
//! - `hash`: A function that returns the hash value of a hash object.
//! - `hash_length`: A function that returns the length of the hash value of a hash object.
//! - `new`: A function that creates a new hash object from a password, salt, and hash algorithm.
//! - `parse`: A function that parses a JSON string into a hash object.
//! - `parse_algorithm`: A function that parses a hash string into a hash algorithm.
//! - `salt`: A function that returns the salt used to hash a password.
//! - `set_hash`: A function that sets the hash value of a hash object.
//! - `set_password`: A function that sets the password of a hash object.
//! - `set_salt`: A function that sets the salt of a hash object.
//! - `to_string_representation`: A function that converts a hash object to a string representation.
//! - `verify`: A function that verifies a password against a hash object.
//!
//! ### Traits
//!
//! The Hash struct also implements the following traits:
//!
//! - `FromStr`: Allows the Hash struct to be converted from a string.
//! - `std::fmt::Display`: Allows the Hash struct to be printed as a string.
//!
//! ### Security and Performance
//!
//! The `Hash (HSH)` library uses the argon2rs crate for the Argon2i algorithm. This library is a secure and quantum-resistant password hashing library. The Bcrypt and Scrypt algorithms are implemented using the bcrypt and scrypt crates respectively. These algorithms are designed to be secure against brute-force attacks and are also considered quantum-resistant. Performance of these algorithms can be tuned by adjusting parameters such as the work factor or memory cost. Always ensure to use a unique salt for each password to prevent rainbow table attacks.
//!
//! ### Recommendations
//!
//! It is recommended to always use the latest version of this library to ensure you have the most up-to-date security features. When handling passwords, always ensure they are hashed before being stored and never log or display passwords in plaintext. Always use a secure and random salt when hashing passwords.
//!
//! ## Getting Started 🚀
//!
//! To start using Hash (HSH), add it as a dependency in your Cargo.toml file and import it in your Rust file. You can then create a new Hash instance and call the appropriate methods for your needs.
//!
//! ## License 📝
//!
//! The project is licensed under the terms of both the MIT license and the
//! Apache License (Version 2.0).
//!
//! - [Apache License, Version 2.0][1]
//! - [MIT license][2]
//!
//! [banner]: https://kura.pro/hsh/images/banners/banner-hsh.svg "The Hash (HSH) Banner"
//! [crate-shield]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006 "Crates.io"
//! [github-shield]: https://img.shields.io/badge/github-555555?style=for-the-badge&labelColor=000000&logo=github "GitHub"
//! [lib-rs-shield]: https://img.shields.io/badge/lib.rs-v0.0.4-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4 "Lib.rs"
//! [license-shield]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B "License"
//! [rust-shield]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust "Rust"
//!
//! [0]: https://minifunctions.com/ "MiniFunctions"
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

/// The `macros` module contains functions for generating macros.
pub mod macros;

extern crate argon2rs;
extern crate base64;
extern crate bcrypt;
extern crate scrypt;
extern crate vrd;
use argon2rs::argon2i_simple;
use base64::{engine::general_purpose, Engine as _};

use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use vrd::Random;

/// A type alias for a salt.
pub type Salt = Vec<u8>;

/// A struct for storing and verifying hashed passwords based on the argon2rs crate
#[non_exhaustive]
#[derive(
    Clone,
    Debug,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct Hash {
    /// The password hash.
    pub hash: Vec<u8>,
    /// The salt used for hashing
    pub salt: Salt,
    /// The hash algorithm used
    pub algorithm: HashAlgorithm,
}

/// The supported hash algorithms
#[non_exhaustive]
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
pub enum HashAlgorithm {
    /// Argon2i
    Argon2i,
    /// Bcrypt
    Bcrypt,
    /// Scrypt
    Scrypt,
}

impl Hash {
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
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Vec<u8>, String> {
        match algo {
            "argon2i" => {
                Ok(argon2i_simple(password, salt).into_iter().collect())
            }
            "bcrypt" => {
                let bcrypt_cost = 12;
                bcrypt::hash(password, bcrypt_cost)
                    .map_err(|e| e.to_string())
                    .map(|hash_parts| hash_parts.into_bytes())
            }
            "scrypt" => {
                let scrypt_params = scrypt::Params::new(14, 8, 1, 64)
                    .map_err(|e| e.to_string())?;
                let mut output = [0u8; 64];
                scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                )
                .map_err(|e| e.to_string())
                .map(|_| output.to_vec())
            }
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
                let hash = argon2i_simple(password, salt);
                Ok(hash.to_vec() == self.hash)
            }
            HashAlgorithm::Bcrypt => {
                let hash_str = std::str::from_utf8(&self.hash)
                    .map_err(|_| "Failed to convert hash to string")?;
                bcrypt::verify(password, hash_str)
                    .map_err(|_| "Failed to verify Bcrypt password")
            }
            HashAlgorithm::Scrypt => {
                let scrypt_params = scrypt::Params::new(14, 8, 1, 64)
                    .map_err(|_| {
                    "Failed to create Scrypt params"
                })?;
                let mut output = [0u8; 64];
                match scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                ) {
                    Ok(_) => Ok(output.to_vec() == self.hash),
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
        "Quantum-Resistant Cryptographic Hash Library for Password Hashing and Verification."
    );
    Ok(())
}
