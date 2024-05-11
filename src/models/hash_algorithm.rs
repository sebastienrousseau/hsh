// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::{Deserialize, Serialize};

/// Represents the different algorithms available for password hashing.
///
/// This enum is used to specify which hashing algorithm should be used
/// when creating a new hashed password.
///
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
    /// Argon2i - A memory-hard password hashing algorithm.
    ///
    /// Resistant against various types of attacks, including:
    /// - GPU-based attacks
    /// - Side-channel attacks
    ///
    /// Incorporates multiple parameters to deter attackers:
    /// - Memory usage
    /// - Parallelism
    /// - Time cost
    Argon2i,

    /// Bcrypt - A widely used, computationally intensive password hashing algorithm.
    ///
    /// Features:
    /// - Based on the Blowfish encryption cipher
    /// - Uses key stretching technique
    /// - Time-consuming and resource-intensive, which makes it resistant to cracking
    Bcrypt,

    /// Scrypt - A memory-hard password hashing algorithm designed for resistance to brute-force attacks.
    ///
    /// Features:
    /// - Consumes a large amount of memory
    /// - Makes parallelized attacks difficult and costly
    Scrypt,
}

/// Represents a generic hashing algorithm.
///
/// The `HashingAlgorithm` trait defines a common interface for hashing algorithms.
/// Implementing this trait for different hashing algorithms ensures that they can be used
/// interchangeably for hashing passwords.
///
/// The primary consumer of this trait is the `Hash` struct, which uses it to handle the hashing
/// logic in a decoupled and extendable manner.
pub trait HashingAlgorithm {
    /// Hashes a given password using a specific salt.
    ///
    /// Given a plaintext `password` and a `salt`, this method returns a hashed representation
    /// of the password. The hashing algorithm used is determined by the implementing type.
    ///
    /// # Parameters
    ///
    /// - `password`: The plaintext password to be hashed.
    /// - `salt`: A cryptographic salt to prevent rainbow table attacks.
    ///
    /// # Returns
    ///
    /// Returns a `Result` containing the hashed password as a vector of bytes.
    /// If hashing fails, returns a `String` detailing the error.
    fn hash_password(
        password: &str,
        salt: &str,
    ) -> Result<Vec<u8>, String>;
}
