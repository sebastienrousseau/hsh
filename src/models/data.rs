// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::HashAlgorithm;
use serde::{Deserialize, Serialize};

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