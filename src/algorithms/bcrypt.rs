// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::models::hash_algorithm::HashingAlgorithm;
use bcrypt::{hash, DEFAULT_COST};
use serde::{Deserialize, Serialize};

/// Implementation of the Bcrypt hashing algorithm.
///
/// `Bcrypt` is a struct that represents the Bcrypt hashing algorithm,
/// which is based on the Blowfish cipher and is particularly effective against brute-force attacks.
///
/// This struct implements the `HashingAlgorithm` trait, providing a concrete implementation
/// for hashing passwords using the Bcrypt algorithm.
///
/// # Features
///
/// - Computationally intensive, making brute-force attacks more difficult.
/// - Uses key stretching to make pre-computed attacks (like rainbow tables) less effective.
///
/// # Examples
///
/// ```
/// use hsh::models::hash_algorithm::HashingAlgorithm;
/// use hsh::algorithms::bcrypt::Bcrypt;
///
/// let password = "supersecret";
/// let salt = "randomsalt";
///
/// let hashed_password = Bcrypt::hash_password(password, salt).unwrap();
/// ```
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
pub struct Bcrypt;

impl HashingAlgorithm for Bcrypt {
    /// Hashes a given password using the Bcrypt algorithm.
    ///
    /// This method computes a hashed representation of the plaintext `password` using the Bcrypt algorithm.
    /// Note that the `salt` parameter is not used in this implementation, as Bcrypt generates its own salt internally.
    ///
    /// # Parameters
    ///
    /// - `password`: The plaintext password to be hashed.
    /// - `_salt`: Unused in this implementation, provided for interface compatibility.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the hashed password as a vector of bytes.
    /// If hashing fails for some reason, returns a `String` detailing the error.
    fn hash_password(
        password: &str,
        _salt: &str,
    ) -> Result<Vec<u8>, String> {
        hash(password, DEFAULT_COST)
            .map_err(|e| e.to_string())
            .map(|hash_parts| hash_parts.into_bytes())
    }
}
