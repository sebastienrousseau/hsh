// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use serde::{Deserialize, Serialize};

/// Represents the different algorithms available for password hashing.
///
/// This enum is used to specify which hashing algorithm should be used
/// when creating a new hashed password.
///
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
