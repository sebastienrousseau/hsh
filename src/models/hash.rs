// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::{Deserialize, Serialize};
use super::hash_algorithm::HashAlgorithm;

/// A type alias for a salt.
pub type Salt = Vec<u8>;

/// A struct for storing and verifying hashed passwords.
/// It uses `#[non_exhaustive]` and derive macros for common functionalities.
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
    /// The salt used for hashing.
    pub salt: Salt,
    /// The hash algorithm used.
    pub algorithm: HashAlgorithm,
}

/// A builder struct for the `Hash` struct.
/// It contains optional fields that correspond to the fields in `Hash`.
/// The `#[derive(Default)]` allows us to initialize all fields to `None`.
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
pub struct HashBuilder {
    /// The password hash.
    hash: Option<Vec<u8>>,
    /// The salt used for hashing.
    salt: Option<Salt>,
    /// The hash algorithm used.
    algorithm: Option<HashAlgorithm>,
}

impl HashBuilder {
    /// Creates a new `HashBuilder` with all fields set to `None`.
    pub fn new() -> Self {
        HashBuilder {
            hash: None,
            salt: None,
            algorithm: None,
        }
    }

    /// Sets the `hash` field in the builder.
    /// The `self` parameter is consumed and returned to allow for method chaining.
    pub fn hash(mut self, hash: Vec<u8>) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Sets the `salt` field in the builder.
    /// The `self` parameter is consumed and returned to allow for method chaining.
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the `algorithm` field in the builder.
    /// The `self` parameter is consumed and returned to allow for method chaining.
    pub fn algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Consumes the builder and returns a `Hash` if all fields are set.
    /// Otherwise, it returns an error.
    pub fn build(self) -> Result<Hash, String> {
        if let (Some(hash), Some(salt), Some(algorithm)) = (self.hash, self.salt, self.algorithm) {
            Ok(Hash {
                hash,
                salt,
                algorithm,
            })
        } else {
            Err("Missing fields".to_string())
        }
    }
}

/// Creates a new `HashBuilder` with all fields set to `None`.
impl Default for HashBuilder {
    fn default() -> Self {
        Self::new()
    }
}

