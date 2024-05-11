// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::models::hash_algorithm::HashingAlgorithm;
use scrypt::scrypt;
use scrypt::Params;
use serde::{Deserialize, Serialize};

/// Implementation of the Scrypt hashing algorithm.
///
/// `Scrypt` is a struct that represents the Scrypt hashing algorithm,
/// which is a memory-hard algorithm designed to be computationally intensive,
/// thereby making it difficult to perform large-scale custom hardware attacks.
///
/// This struct implements the `HashingAlgorithm` trait, providing a concrete implementation
/// for hashing passwords using the Scrypt algorithm.
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
pub struct Scrypt;

impl HashingAlgorithm for Scrypt {
    /// Hashes a given password using the Scrypt algorithm.
    ///
    /// Given a plaintext `password` and a `salt`, this method returns a hashed representation
    /// of the password using the Scrypt algorithm.
    ///
    /// # Parameters
    ///
    /// - `password`: The plaintext password to be hashed.
    /// - `salt`: A cryptographic salt to prevent rainbow table attacks.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the hashed password as a vector of bytes.
    /// If hashing fails for some reason, it returns a `String` detailing the error.
    fn hash_password(
        password: &str,
        salt: &str,
    ) -> Result<Vec<u8>, String> {
        // The `Params` struct is initialized with specific parameters that define the
        // computational cost of the hashing process. The parameters used here are chosen
        // to provide a balance between security and performance. Adjust these values based
        // on the security requirements and the expected computational capacity.
        let params =
            Params::new(14, 8, 1, 64).map_err(|e| e.to_string())?;
        let mut output = [0u8; 64];
        scrypt(
            password.as_bytes(),
            salt.as_bytes(),
            &params,
            &mut output,
        )
        .map_err(|e| e.to_string())
        .map(|_| output.to_vec())
    }
}
