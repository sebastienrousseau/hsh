// Copyright © 2022-2023 Mini Functions. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT
//!
//! # Quantum-Resistant Cryptographic Hash Library for Password Hashing and Verification in Rust
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
//! ## Overview
//!
//! The Hash (HSH) library is a cryptographic hash library for password
//! hashing and verification in Rust, designed to provide robust
//! security for passwords, utilizing the latest advancements in
//! quantum-resistant cryptography.
//!
//! The library is designed to be easy to use, with a simple API that
//! allows for the generation, retrieval, and verification of password
//! hashes.
//!
//! It supports the following hash algorithms:
//!
//! - [**Argon2i**](<https://en.wikipedia.org/wiki/Argon2>): A memory-
//! hard password hashing function designed to be secure against both
//! brute-force attacks and rainbow table attacks.
//! - [**Bcrypt**](<https://en.wikipedia.org/wiki/Bcrypt>): A password
//! hashing function designed to be secure against brute-force attacks.
//! It is a work-factor function, which means that it takes a certain
//! amount of time to compute. This makes it difficult to attack with a
//! brute-force algorithm.
//! - [**Scrypt**](<https://en.wikipedia.org/wiki/Scrypt>): A password
//! hashing function designed to be secure against both brute-force
//! attacks and rainbow table attacks. It is a memory-hard and work-
//! factor function, which means that it requires a lot of memory and
//! time to compute. This makes it very difficult to attack with a GPU
//! or other parallel computing device.
//!
//! ## Features
//!
//! ### Hash Struct
//!
//! The `Hash` struct has three fields:
//!
//! - `password`: A string that stores the plaintext password.
//! - `hash`: A vector of bytes that stores the hashed password.
//! - `salt`: A vector of bytes that stores the salt used for password
//! hashing.
//! - `algorithm`: An enum that stores the algorithm used for password
//! hashing. The enum has three variants: `Argon2i`, `Bcrypt`, and
//! `Scrypt`.
//!
//! ### Hash Algorithms
//!
//! The `HashAlgorithm` enum has three variants:
//! - `Argon2i`: The Argon2i algorithm.
//! - `Bcrypt`: The Bcrypt algorithm.
//! - `Scrypt`: The Scrypt algorithm.
//!
//! ### Hash Methods
//!
//! The `Hash` struct provides the following methods for password
//! hashing and verification:
//!
//! - `from_hash`: A method that creates a `Hash` struct instance from a given hash.
//! - `from_string`: A method that creates a `Hash` struct instance from a given string.
//! - `generate_hash`: A static method that generates a hash from a plaintext password and salt.
//! - `generate_salt`: A static method that generates a salt.
//! - `hash_length`: A method that returns the length of the hash.
//! - `hash`: A method that returns the hash as a slice of bytes.
//! - `new`: A constructor method that creates a new `Hash` struct instance with the given plaintext password and salt.
//! - `password_length`: A method that returns the length of the password.
//! - `password`: A method that returns the password as a string.
//! - `salt`: A method that returns the salt as a slice of bytes.
//! - `set_hash`: A method that sets a new hash.
//! - `set_password`: A method that sets a new password and generates a new hash.
//! - `set_salt`: A method that sets a new salt.
//! - `to_string_representation`: A method that returns the hash as a string.
//! - `verify`: A method that verifies a plaintext password against the stored hash.
//!
//! ### Traits
//!
//! The `Hash` struct also implements the following traits:
//!
//! - `FromStr`: Allows the `Hash` struct to be converted from a string.
//! - `std::fmt::Display`: Allows the `Hash` struct to be printed as a string.
//!
//! ### Security and Performance
//!
//! It is important to note that the library uses the `argon2rs` crate for password hashing, which is a secure and quantum-resistant password hashing library.
//!
//! ## Usage
//!
//! - [`serde`][]: Enable serialization/deserialization via serde
//!
//!
//! [`serde`]: https://github.com/serde-rs/serde
//! [banner]: https://kura.pro/hsh/images/banners/banner-hsh.svg "The Hash (HSH) Banner"
//! [crate-shield]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006 "Crates.io"
//! [github-shield]: https://img.shields.io/badge/github-555555?style=for-the-badge&labelColor=000000&logo=github "GitHub"
//! [lib-rs-shield]: https://img.shields.io/badge/lib.rs-v0.0.3-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4 "Lib.rs"
//! [license-shield]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B "License"
//! [rust-shield]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust "Rust"
//!
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
use bcrypt::hash_with_salt;
use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use vrd::*;

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
    /// The password.
    pub password: String,
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
    /// Generates a hash from a password, salt and algorithm type. The
    /// algorithm type is used to determine which hash algorithm to use.
    ///
    /// These are the supported hash algorithms:
    ///
    /// * `Argon2i` is a password hashing function that is designed to
    ///             be secure against both brute-force attacks and
    ///             rainbow table attacks. It is a memory-hard function,
    ///             which means that it requires a lot of memory to
    ///             compute. This makes it difficult to attack with a
    ///             GPU or other parallel computing device.
    ///
    /// * `Bcrypt` is a password hashing function that is designed to
    ///            be secure against brute-force attacks. It is a work-
    ///            factor function, which means that it takes a certain
    ///            amount of time to compute. This makes it difficult to
    ///            attack with a brute-force algorithm.
    ///
    /// * `Scrypt` is a password hashing function that is designed to be
    ///            secure against both brute-force attacks and rainbow
    ///            table attacks. It is a memory-hard and work-factor
    ///            function, which means that it requires a lot of
    ///            memory and time to compute. This makes it very
    ///            difficult to attack with a GPU or other parallel
    ///            computing device.
    ///
    /// ## Arguments
    ///
    /// * `password` - The password to hash.
    /// * `salt` - The salt to use.
    /// * `algo` - The algorithm to use. Supported algorithms are
    ///            `argon2i`, `bcrypt` and `scrypt`.
    ///
    /// ## Returns
    ///
    /// A vector of bytes representing the hash. The length of the hash
    /// depends on the algorithm used.
    ///
    /// ## Panics
    ///
    /// The function panics if the algorithm is not supported.
    ///
    /// ## Example
    ///
    /// ```rust
    ///
    /// use hsh::{Hash,generate_hash};
    ///
    /// fn main() {
    ///     let mut password = "secret";
    ///     let salt = "somesalt";
    ///
    ///     // Generate an Argon2i hash
    ///     let argon2i_hash = generate_hash!(password, salt, "argon2i");
    ///     println!("Argon2i hash: {:?}", argon2i_hash);
    ///
    ///     // Generate a bcrypt hash
    ///     let bcrypt_hash = generate_hash!(password, salt, "bcrypt");
    ///     println!("bcrypt hash: {:?}", bcrypt_hash);
    ///
    ///     // Generate a scrypt hash
    ///     let scrypt_hash = generate_hash!(password, salt, "scrypt");
    ///     println!("scrypt hash: {:?}", scrypt_hash);
    /// }
    /// ```
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Vec<u8> {
        match algo {
            "argon2i" => {
                argon2i_simple(password, salt).into_iter().collect()
            }
            "bcrypt" => {
                let bcrypt_cost = 12;
                let mut salt_array = [0u8; 16];
                let salt_bytes = salt.as_bytes();
                salt_array[..salt_bytes.len()]
                    .copy_from_slice(salt_bytes);
                let hash_parts =
                    hash_with_salt(password, bcrypt_cost, salt_array)
                        .unwrap();
                format!("{:?}", hash_parts).into_bytes()
            }
            "scrypt" => {
                let scrypt_params =
                    scrypt::Params::new(14, 8, 1, 64).unwrap();
                let mut output = [0u8; 64];
                match scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                ) {
                    Ok(_) => output.to_vec(),
                    Err(e) => return e.to_string().into_bytes(),
                }
            }
            _ => panic!("Unsupported hash algorithm: {}", algo),
        }
    }

    /// Returns the hash.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Generates a salt string for password hashing using the specified hash algorithm.
    ///
    /// # Arguments
    ///
    /// * algo - A string slice representing the hash algorithm. Currently supported options are "argon2i", "bcrypt", and "scrypt".
    ///
    /// # Returns
    ///
    /// A String representing the generated salt.
    ///
    pub fn generate_salt(algo: &str) -> String {
        match algo {
            "argon2i" => Self::generate_random_string(16),
            "bcrypt" => {
                let mut rng = Random::default();
                let salt: [u8; 16] = rng.bytes(16).try_into().unwrap();
                general_purpose::STANDARD.encode(&salt[..])
            }
            "scrypt" => {
                let mut rng = Random::default();
                let salt: [u8; 32] = rng.bytes(32).try_into().unwrap();
                general_purpose::STANDARD.encode(&salt[..])
            }
            _ => panic!("Unsupported hash algorithm: {}", algo),
        }
    }

    fn generate_random_string(len: usize) -> String {
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

    /// Returns the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Get the hash algorithm used by this hash
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Returns the length of the hash.
    pub fn hash_length(&self) -> usize {
        self.hash.len()
    }

    /// Returns the password.
    pub fn new(password: &str, salt: &str, algo: &str) -> Self {
        if password.len() < 8 || password.len() > 0xffffffff {
            panic!("Password length must be between 8 and 0xffffffff, inclusive");
        }
        if salt.len() < 8 || salt.len() > 0xffffffff {
            panic!("Salt length must be between 8 and 0xffffffff, inclusive");
        }
        if !["argon2i", "bcrypt", "scrypt"].contains(&algo) {
            panic!("Unsupported hash algorithm: {}", algo);
        }

        let hash = Self::generate_hash(password, salt, algo);
        Self {
            password: password.to_string(),
            hash,
            salt: salt.as_bytes().to_vec(),
            algorithm: match algo {
                "argon2i" => HashAlgorithm::Argon2i,
                "bcrypt" => HashAlgorithm::Bcrypt,
                "scrypt" => HashAlgorithm::Scrypt,
                _ => panic!("Unsupported hash algorithm: {}", algo),
            },
        }
    }

    /// Returns the password.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the password length.
    pub fn password_length(&self) -> usize {
        self.password.len()
    }

    /// Sets the password and generates a new hash.
    pub fn set_password(
        &mut self,
        password: &str,
        salt: &str,
        algo: &str,
    ) {
        self.password = password.to_string();
        self.hash = Self::generate_hash(password, salt, algo);
    }

    /// Verifies the password against the hash.
    pub fn verify_password(&mut self, password: &str) -> bool {
        let hashed_password = match self.algorithm() {
            HashAlgorithm::Argon2i | HashAlgorithm::Scrypt => {
                self.hash()
            }
            HashAlgorithm::Bcrypt => {
                let hash_str =
                    std::str::from_utf8(self.hash()).unwrap();
                bcrypt::verify(password, hash_str).unwrap_or(false);
                self.hash()
            }
        };
        bcrypt::verify(
            password,
            &String::from_utf8_lossy(hashed_password).to_string(),
        )
        .unwrap_or(false)
    }

    /// Sets the hash.
    pub fn set_hash(&mut self, hash: &[u8]) {
        self.hash = hash.to_vec();
    }

    /// Sets the salt.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }
    /// Gets the entropy of the hash in bits.
    pub fn from_hash(hash: &[u8], algo: &str) -> Self {
        Hash {
            password: String::new(),
            salt: Vec::new(),
            hash: hash.to_vec(),
            algorithm: match algo {
                "argon2i" => HashAlgorithm::Argon2i,
                "bcrypt" => HashAlgorithm::Bcrypt,
                "scrypt" => HashAlgorithm::Scrypt,
                _ => panic!("Unsupported hash algorithm: {}", algo),
            },
        }
    }
    /// Parses a `Hash` object from a hash string in the format used by the `argon2` crate.
    ///
    /// The hash string should have the following format:
    ///
    /// `$<algorithm>$v=<version>$m=<memory>$t=<time>$p=<parallelism>$<salt>$<hash>`
    ///
    /// where:
    ///
    /// * `<algorithm>` is the name of the algorithm used to generate the hash (e.g., `argon2i`)
    /// * `<version>` is the version of the algorithm used (e.g., `19`)
    /// * `<memory>` is the amount of memory used by the algorithm (e.g., `4096`)
    /// * `<time>` is the amount of time used by the algorithm (e.g., `3`)
    /// * `<parallelism>` is the degree of parallelism used by the algorithm (e.g., `1`)
    /// * `<salt>` is the salt used to generate the hash (encoded in base64)
    /// * `<hash>` is the hash value (encoded in base64)
    ///
    /// # Arguments
    ///
    /// * `hash_str`: A string representing the hash to parse.
    ///
    /// # Returns
    ///
    /// A `Hash` object representing the parsed hash.
    ///
    /// # Panics
    ///
    /// Panics if the input string is not a valid hash string in the expected format.
    ///
    pub fn from_string(hash_str: &str) -> Self {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() != 6 {
            panic!("Invalid hash string");
        }
        let algorithm = Self::parse_algorithm(hash_str);
        let password = parts[5];
        let salt = format!(
            "${}${}${}${}",
            parts[1], parts[2], parts[3], parts[4]
        );
        let hash = parts[5];

        Hash {
            password: password.to_string(),
            salt: salt.as_bytes().to_vec(),
            hash: hash.as_bytes().to_vec(),
            algorithm,
        }
    }

    /// Parses a hash string and returns the corresponding hash algorithm.
    ///
    /// # Arguments
    ///
    /// * `hash_str` - A string containing the hash in the format `"$algorithm$parameters$hash"`.
    ///
    /// # Examples
    ///
    /// ```rust
    ///
    /// use hsh::Hash;
    /// use hsh::HashAlgorithm;
    ///
    /// let hash_str = "$argon2i$v=19$m=4096,t=3,p=1$c2FsdDM0NTQ$XHD8WkLbGxwOyN0exjK72RTJnAdubKjFz3nqP/CjKcw";
    /// let algorithm = Hash::parse_algorithm(hash_str);
    /// assert_eq!(algorithm, HashAlgorithm::Argon2i);
    ///
    /// ```
    pub fn parse_algorithm(hash_str: &str) -> HashAlgorithm {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 2 {
            panic!("Invalid hash string");
        }
        match parts[1] {
            "argon2i" => HashAlgorithm::Argon2i,
            "bcrypt" => HashAlgorithm::Bcrypt,
            "scrypt" => HashAlgorithm::Scrypt,
            _ => panic!("Unsupported hash algorithm"),
        }
    }

    /// Verifies a password against the stored hash.
    pub fn verify(&self, password: &str) -> bool {
        let salt = String::from_utf8(self.salt.to_vec()).unwrap();
        match self.algorithm {
            HashAlgorithm::Argon2i => {
                let hash = argon2i_simple(password, &salt);
                hash.to_vec() == self.hash
            }
            HashAlgorithm::Bcrypt => {
                let hash = bcrypt::hash(password, 4).unwrap();
                match bcrypt::verify(password, &hash) {
                    Ok(result) => result,
                    Err(_) => false,
                }
            }
            HashAlgorithm::Scrypt => {
                let scrypt_params =
                    scrypt::Params::new(14, 8, 1, 64).unwrap();
                let mut output = [0u8; 64];
                match scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                ) {
                    Ok(_) => output.to_vec() == self.hash,
                    Err(_) => false,
                }
            }
        }
    }

    // pub fn verify(&self, password: &str) -> bool {
    //     let salt = String::from_utf8(self.salt.to_vec()).unwrap();
    //     let hash = argon2i_simple(password, &salt);
    //     hash.to_vec() == self.hash
    // }

    /// Returns the hash as a string.
    pub fn to_string_representation(&self) -> String {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{b:x}"))
            .collect::<Vec<String>>()
            .join("");

        format!(
            "{}:{}:{}",
            self.password,
            String::from_utf8(self.salt.to_vec()).unwrap(),
            hash_str
        )
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Hash {{ password: {}, hash: {:?} }}",
            self.password, self.hash
        )
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
