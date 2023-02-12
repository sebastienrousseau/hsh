// Copyright © 2022-2023 Mini Functions. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT
//!
//! # Quantum-Resistant Cryptographic Hash Library for Password Hashing and Verification in Rust
//!
//! [![Rust](https://raw.githubusercontent.com/sebastienrousseau/vault/main/assets/mini-functions/logo/logo-hsh.svg)](https://minifunctions.com)
//!
//! <center>
//!
//! [![Rust](https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust)](https://www.rust-lang.org)
//! [![Crates.io](https://img.shields.io/crates/v/hsh.svg?style=for-the-badge&color=success&labelColor=27A006)](https://crates.io/crates/hsh)
//! [![Lib.rs](https://img.shields.io/badge/lib.rs-v0.0.2-success.svg?style=for-the-badge&color=8A48FF&labelColor=6F36E4)](https://lib.rs/crates/hsh)
//! [![GitHub](https://img.shields.io/badge/github-555555?style=for-the-badge&labelColor=000000&logo=github)](https://github.com/sebastienrousseau/hsh)
//! [![License](https://img.shields.io/crates/l/hsh.svg?style=for-the-badge&color=007EC6&labelColor=03589B)](http://opensource.org/licenses/MIT)
//!
//! </center>
//!
//! ## Overview
//!
//! The Hash (HSH) library is a cryptographic hash library for password
//! hashing and verification in Rust, based on the `argon2rs` crate.
//!
//! This library is designed to provide robust security for passwords,
//! utilizing the latest advancements in quantum-resistant cryptography.
//!
//! It is based on the `argon2rs` crate. The library implements a struct
//! named `Hash` that provides various methods for password hash
//! generation, retrieval, and verification.
//!
//! ## Features
//!
//! ### Hash Struct
//!
//! The `Hash` struct has three fields:
//!
//! - `password`: A string that stores the plaintext password.
//! - `hash`: A vector of bytes that stores the hashed password.
//! - `salt`: A vector of bytes that stores the salt used for password hashing.
//!
//! ### Hash Methods
//!
//! The `Hash` struct provides the following methods for password hashing and verification:
//!
//! - `generate_hash`: A static method that generates a hash from a plaintext password and salt.
//! - `hash`: A method that returns the hash as a slice of bytes.
//! - `salt`: A method that returns the salt as a slice of bytes.
//! - `hash_length`: A method that returns the length of the hash.
//! - `new`: A constructor method that creates a new `Hash` struct instance with the given plaintext password and salt.
//! - `password`: A method that returns the password as a string.
//! - `password_length`: A method that returns the length of the password.
//! - `set_password`: A method that sets a new password and generates a new hash.
//! - `set_hash`: A method that sets a new hash.
//! - `set_salt`: A method that sets a new salt.
//! - `from_hash`: A method that creates a `Hash` struct instance from a given hash.
//! - `verify`: A method that verifies a plaintext password against the stored hash.
//! - `to_string_representation`: A method that returns the hash as a string.
//!
//! ### Traits
//!
//! The `Hash` struct also implements the following traits:
//!
//! - `FromStr`: Allows the `Hash` struct to be converted from a string.
//! - `std::fmt::Display`: Allows the `Hash` struct to be printed as a string.
//!
//! ### Macros
//!
//! The library also provides several macros for common operations on the `Hash` struct:
//!
//! - `password_length`: Returns the length of the password for a given `Hash` struct instance.
//! - `set_hash`: Sets a new hash value for a given `Hash` struct instance.
//! - `set_password`: Sets a new password and salt value for a given `Hash` struct instance.
//! - `set_salt`: Sets a new salt value for a given `Hash` struct instance.
//! - `generate_hash`: Generates a new hash for a given password and salt.
//! - `verify_password`: Verifies if the password matches the hash of a given `Hash` struct instance.
//! - `new_hash`: Creates a new instance of the `Hash` struct with the given password and salt.
//! - `display_hash`: Prints the hash of a given `Hash` struct instance to the console.
//! - `to_string`: Converts a given `Hash` struct instance to a string.
//!
//! ### Security and Performance
//!
//! It is important to note that the library uses the `argon2rs` crate for password hashing, which is a secure and quantum-resistant password hashing library.
//!
//! ## Usage
//!
//! - [`serde`][]: Enable serialization/deserialization via serde
//!
//! [`serde`]: https://github.com/serde-rs/serde
//!
#![cfg_attr(feature = "bench", feature(test))]
#![deny(dead_code)]
#![deny(missing_debug_implementations)]
#![deny(missing_docs)]
#![forbid(unsafe_code)]
#![warn(unreachable_pub)]
#![doc(
    html_favicon_url = "https://raw.githubusercontent.com/sebastienrousseau/vault/main/assets/hsh/icons/ico-hsh.svg",
    html_logo_url = "https://raw.githubusercontent.com/sebastienrousseau/vault/main/assets/hsh/icons/ico-hsh.svg",
    html_root_url = "https://docs.rs/hsh"
)]
#![crate_name = "hsh"]
#![crate_type = "lib"]

extern crate argon2rs;
use argon2rs::argon2i_simple;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// A type alias for a salt.
pub type Salt = Vec<u8>;

/// A struct for storing and verifying hashed passwords based on the argon2rs crate
#[non_exhaustive]
#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Hash {
    /// The password.
    pub password: String,
    /// The password hash.
    pub hash: Vec<u8>,
    /// The salt used for hashing
    pub salt: Salt,
}

impl Hash {
    /// Generates a hash from a password and salt.
    pub fn generate_hash(password: &str, salt: &str) -> Vec<u8> {
        argon2i_simple(password, salt).into_iter().collect()
    }

    /// Returns the hash.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Returns the salt.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Returns the length of the hash.
    pub fn hash_length(&self) -> usize {
        self.hash.len()
    }

    /// Returns the password.
    pub fn new(password: &str, salt: &str) -> Self {
        if password.len() < 8 || password.len() > 0xffffffff {
            panic!("Password length must be between 8 and 0xffffffff, inclusive");
        }
        if salt.len() < 8 || salt.len() > 0xffffffff {
            panic!("Salt length must be between 8 and 0xffffffff, inclusive");
        }
        let hash = Self::generate_hash(password, salt);
        Self {
            password: password.to_string(),
            hash,
            salt: salt.as_bytes().to_vec(),
        }
    }
    // pub fn new(password: &str, salt: &str) -> Self {
    //     let hash = Self::generate_hash(password, salt);
    //     Self {
    //         password: password.to_string(),
    //         hash,
    //         salt: salt.as_bytes().to_vec(),
    //     }
    // }

    /// Returns the password.
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the password length.
    pub fn password_length(&self) -> usize {
        self.password.len()
    }

    /// Sets the password and generates a new hash.
    pub fn set_password(&mut self, password: &str, salt: &str) {
        self.password = password.to_string();
        self.hash = Self::generate_hash(password, salt);
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
    pub fn from_hash(hash: &[u8]) -> Self {
        Hash {
            password: String::new(),
            salt: Vec::new(),
            hash: hash.to_vec(),
        }
    }

    /// Verifies a password against the stored hash.
    pub fn verify(&self, password: &str) -> bool {
        let salt = String::from_utf8(self.salt.to_vec()).unwrap();
        let hash = argon2i_simple(password, &salt);
        hash.to_vec() == self.hash
    }
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

impl std::fmt::Display for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Hash {{ password: {}, hash: {:?} }}",
            self.password, self.hash
        )
    }
}

impl FromStr for Hash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() != 3 {
            return Err(String::from("Invalid string format"));
        }
        let password = parts[0];
        let salt = parts[1];

        if password.len() < 8 || password.len() > 0xffffffff {
            return Err(String::from(
                "Password length must be between 8 and 0xffffffff, inclusive",
            ));
        }

        Ok(Hash::new(password, salt))
    }
}

/// This macro returns the length of the password for a given Hash
/// struct instance.
#[macro_export]
macro_rules! password_length {
    ($hash:expr) => {
        $hash.password_length()
    };
}

/// This macro sets a new hash value for a given Hash struct instance.
#[macro_export]
macro_rules! set_hash {
    ($hash:expr, $new_hash:expr) => {
        $hash.set_hash($new_hash)
    };
}

/// This macro sets a new password and salt value for a given Hash
/// struct instance.
#[macro_export]
macro_rules! set_password {
    ($hash:expr, $new_password:expr, $salt:expr) => {
        $hash.set_password($new_password, $salt)
    };
}

/// This macro sets a new salt value for a given Hash struct instance.
#[macro_export]
macro_rules! set_salt {
    ($hash:expr, $new_salt:expr) => {
        $hash.set_salt($new_salt)
    };
}

/// This macro generates a new hash for a given password and salt.
#[macro_export]
macro_rules! generate_hash {
    ($password:expr, $salt:expr) => {
        Hash::generate_hash($password, $salt)
    };
}

/// This macro verifies if the password matches the hash of a given
/// Hash struct instance.
#[macro_export]
macro_rules! verify_password {
    ($hash:expr, $password:expr) => {
        $hash.verify($password)
    };
}

/// This macro creates a new instance of the Hash struct with the given
/// password and salt.
#[macro_export]
macro_rules! new_hash {
    ($password:expr, $salt:expr) => {
        Hash::new($password, $salt)
    };
}

/// This macro prints the hash of a given Hash struct instance to the
/// console.
#[macro_export]
macro_rules! display_hash {
    ($hash:expr) => {
        println!("{}", $hash)
    };
}

/// This macro converts a given Hash struct instance to a string.
#[macro_export]
macro_rules! to_string {
    ($hash:expr) => {
        $hash.to_string_representation()
    };
}
