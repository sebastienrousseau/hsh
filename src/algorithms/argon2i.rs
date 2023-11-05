// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::models::hash_algorithm::HashingAlgorithm;
use argon2rs::argon2i_simple;
use serde::{Serialize, Deserialize};

/// Implementation of the Argon2i hashing algorithm.
///
/// `Argon2i` is a struct that represents the Argon2i hashing algorithm,
/// which is a memory-hard algorithm resistant to GPU-based attacks and side-channel attacks.
/// It is one of the multiple hashing algorithms that can be used for password hashing in this library.
///
/// This struct implements the `HashingAlgorithm` trait, providing a concrete implementation
/// for hashing passwords using the Argon2i algorithm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Argon2i;

impl HashingAlgorithm for Argon2i {
    /// Hashes a given password using the Argon2i algorithm.
    ///
    /// This method computes a hashed representation of the plaintext `password` using the Argon2i algorithm,
    /// combined with the provided `salt` for added security.
    ///
    /// # Parameters
    ///
    /// - `password`: The plaintext password to be hashed.
    /// - `salt`: A cryptographic salt to prevent rainbow table attacks.
    ///
    /// # Returns
    ///
    /// Returns a `Result` with `Ok`, containing the hashed password as a vector of bytes.
    /// Currently, this function does not handle hashing errors and will always return `Ok`.
    fn hash_password(password: &str, salt: &str) -> Result<Vec<u8>, String> {
        Ok(argon2i_simple(password, salt).into_iter().collect())
    }
}
