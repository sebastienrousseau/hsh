// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Core `Hash` type for storing and verifying password hashes.
//!
//! ## Phase 0 hardening (v0.0.9)
//!
//! - **S1**: verify paths use [`subtle::ConstantTimeEq`] for the bytes
//!   comparison, eliminating the prefix-by-prefix timing side-channel.
//! - **S3**: `hash`, `salt`, and any password material are wiped from memory
//!   on drop via [`zeroize::ZeroizeOnDrop`]; the fields are no longer `pub`.
//! - **S7**: every fallible operation returns [`crate::error::Error`].
//! - All `println!` of hashes / salts / passwords during verification has
//!   been removed; the old code logged secrets to stdout.
//!
//! Phase 1 (issue #140) replaces this struct with a PHC-string-format
//! design built on the RustCrypto `password-hash` trait.

use super::hash_algorithm::HashAlgorithm;
use crate::algorithms;
use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use algorithms::{argon2i::Argon2i, bcrypt::Bcrypt, scrypt::Scrypt};
use argon2rs::argon2i_simple;
use base64::{engine::general_purpose, Engine as _};
use scrypt::scrypt;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
use vrd::random::Random;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A type alias for a salt.
pub type Salt = Vec<u8>;

/// Stores a hashed password together with its salt and the algorithm used.
///
/// Internal fields are private and zeroed on drop. Use the
/// [`hash`](Self::hash), [`salt`](Self::salt), and
/// [`algorithm`](Self::algorithm) accessors to read them.
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
    ZeroizeOnDrop,
)]
pub struct Hash {
    /// The password hash bytes — zeroed on drop.
    hash: Vec<u8>,
    /// The salt used for hashing — zeroed on drop.
    salt: Salt,
    /// The hash algorithm used. `HashAlgorithm` carries no secret, so
    /// zeroing it would be a no-op anyway; skipped to avoid requiring a
    /// `Zeroize` impl on the enum.
    #[zeroize(skip)]
    algorithm: HashAlgorithm,
}

impl Hash {
    /// Creates a new `Hash` instance using Argon2i algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::{Hash, Salt};
    ///
    /// let password = "my_password";
    /// let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let _ = Hash::new_argon2i(password, salt);
    /// ```
    pub fn new_argon2i(password: &str, salt: Salt) -> Result<Self> {
        let salt_str = std::str::from_utf8(&salt)?;
        let calculated_hash =
            argon2i_simple(password, salt_str).to_vec();

        HashBuilder::new()
            .hash(calculated_hash)
            .salt(salt)
            .algorithm(HashAlgorithm::Argon2i)
            .build()
    }

    /// Creates a new `Hash` instance using Bcrypt algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::Hash;
    ///
    /// let _ = Hash::new_bcrypt("my_password", 4);
    /// ```
    pub fn new_bcrypt(password: &str, cost: u32) -> Result<Self> {
        let hashed_password = bcrypt::hash(password, cost)
            .map_err(|e| Error::Hashing(e.to_string()))?;

        HashBuilder::new()
            .hash(hashed_password.into_bytes())
            .salt(Vec::new())
            .algorithm(HashAlgorithm::Bcrypt)
            .build()
    }

    /// Creates a new `Hash` instance using Scrypt algorithm for password hashing.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::{Hash, Salt};
    ///
    /// let password = "my_password";
    /// let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    ///
    /// let _ = Hash::new_scrypt(password, salt);
    /// ```
    pub fn new_scrypt(password: &str, salt: Salt) -> Result<Self> {
        let salt_str = std::str::from_utf8(&salt)?;
        let calculated_hash =
            Scrypt::hash_password(password, salt_str)?;

        HashBuilder::new()
            .hash(calculated_hash)
            .salt(salt)
            .algorithm(HashAlgorithm::Scrypt)
            .build()
    }

    /// Returns the hashing algorithm used by this hash.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// Builds a `Hash` from existing hash bytes and an algorithm tag.
    pub fn from_hash(hash: &[u8], algo: &str) -> Result<Self> {
        let algorithm = parse_algorithm_tag(algo)?;
        Ok(Hash {
            salt: Vec::new(),
            hash: hash.to_vec(),
            algorithm,
        })
    }

    /// Parses a serialized hash string in the legacy `$algo$...$hash` form.
    ///
    /// **Note:** this is **not** PHC-compliant. Phase 1 (issue #159) replaces
    /// this with `password_hash::PasswordHashString`.
    pub fn from_string(hash_str: &str) -> Result<Self> {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() != 6 {
            return Err(Error::InvalidHashString(
                "expected 6 fields separated by '$'",
            ));
        }
        let algorithm = Self::parse_algorithm(hash_str)?;
        let salt = format!(
            "${}${}${}${}",
            parts[1], parts[2], parts[3], parts[4]
        );
        let hash_bytes = general_purpose::STANDARD.decode(parts[5])?;
        Ok(Hash {
            salt: salt.into_bytes(),
            hash: hash_bytes,
            algorithm,
        })
    }

    /// Generates a fresh hash for `password` with the given `salt` and
    /// algorithm tag.
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Vec<u8>> {
        match algo {
            "argon2i" => Argon2i::hash_password(password, salt),
            "bcrypt" => Bcrypt::hash_password(password, salt),
            "scrypt" => Scrypt::hash_password(password, salt),
            other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Generates a random alphanumeric string of length `len`.
    ///
    /// **Note:** this uses `vrd::random::Random` for backwards compatibility.
    /// Phase 1 (issue #162) switches salt generation to `OsRng`.
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

    /// Generates a salt suitable for the named algorithm.
    pub fn generate_salt(algo: &str) -> Result<String> {
        let mut rng = Random::default();
        match algo {
            "argon2i" => Ok(Self::generate_random_string(16)),
            "bcrypt" => {
                let salt: Vec<u8> = rng.bytes(16);
                let salt_array: [u8; 16] =
                    salt.try_into().map_err(|_| {
                        Error::InvalidSalt("expected 16 bytes")
                    })?;
                Ok(general_purpose::STANDARD.encode(salt_array))
            }
            "scrypt" => {
                let salt: Vec<u8> = rng.bytes(32);
                let salt_array: [u8; 32] =
                    salt.try_into().map_err(|_| {
                        Error::InvalidSalt("expected 32 bytes")
                    })?;
                Ok(general_purpose::STANDARD.encode(salt_array))
            }
            other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Returns the hash bytes.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// Returns the length of the hash bytes.
    pub fn hash_length(&self) -> usize {
        self.hash.len()
    }

    /// Builds a `Hash` from a `password`, `salt`, and algorithm tag.
    pub fn new(password: &str, salt: &str, algo: &str) -> Result<Self> {
        if password.len() < 8 {
            return Err(Error::InvalidPassword(
                "must be at least 8 characters",
            ));
        }
        let hash = Self::generate_hash(password, salt, algo)?;
        let algorithm = parse_algorithm_tag(algo)?;
        Ok(Self {
            hash,
            salt: salt.as_bytes().to_vec(),
            algorithm,
        })
    }

    /// Parses a JSON string into a [`struct@Hash`].
    pub fn parse(input: &str) -> Result<Self> {
        Ok(serde_json::from_str(input)?)
    }

    /// Extracts the algorithm marker from a legacy serialized hash string.
    pub fn parse_algorithm(hash_str: &str) -> Result<HashAlgorithm> {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 2 {
            return Err(Error::InvalidHashString(
                "missing algorithm marker",
            ));
        }
        parse_algorithm_tag(parts[1])
    }

    /// Returns the salt bytes.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// Sets the hash bytes.
    pub fn set_hash(&mut self, hash: &[u8]) {
        self.hash.zeroize();
        self.hash = hash.to_vec();
    }

    /// Re-hashes `password` with `salt` under `algo` and replaces the
    /// stored hash.
    pub fn set_password(
        &mut self,
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<()> {
        let new_hash = Self::generate_hash(password, salt, algo)?;
        self.hash.zeroize();
        self.hash = new_hash;
        Ok(())
    }

    /// Sets the salt bytes.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt.zeroize();
        self.salt = salt.to_vec();
    }

    /// Converts the hash to a `salt:hex` debug string. **Not PHC.**
    pub fn to_string_representation(&self) -> String {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");
        format!("{}:{}", String::from_utf8_lossy(&self.salt), hash_str)
    }

    /// Verifies `password` against this hash.
    ///
    /// **Constant-time:** the byte comparison uses
    /// [`subtle::ConstantTimeEq`] so timing does not leak how much of the
    /// candidate matched. The bcrypt path delegates to the `bcrypt` crate,
    /// which also uses `subtle` internally.
    ///
    /// Returns `Ok(true)` if the password matches, `Ok(false)` if it does
    /// not, or an [`Error`] if the stored material is malformed.
    pub fn verify(&self, password: &str) -> Result<bool> {
        let salt = std::str::from_utf8(&self.salt)?;

        match self.algorithm {
            HashAlgorithm::Argon2i => {
                let calculated_hash =
                    argon2i_simple(password, salt).to_vec();
                Ok(bool::from(calculated_hash.ct_eq(&self.hash)))
            }
            HashAlgorithm::Bcrypt => {
                let hash_str = std::str::from_utf8(&self.hash)?;
                bcrypt::verify(password, hash_str).map_err(|_| {
                    Error::Verification("bcrypt verify failed")
                })
            }
            HashAlgorithm::Scrypt => {
                let scrypt_params = scrypt::Params::new(14, 8, 1, 64)
                    .map_err(|e| {
                    Error::InvalidParameter(e.to_string())
                })?;
                let mut output = [0u8; 64];
                scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                )
                .map_err(|e| Error::Hashing(e.to_string()))?;
                let ok = bool::from(output.ct_eq(&self.hash));
                output.zeroize();
                Ok(ok)
            }
        }
    }
}

fn parse_algorithm_tag(algo: &str) -> Result<HashAlgorithm> {
    match algo {
        "argon2i" => Ok(HashAlgorithm::Argon2i),
        "bcrypt" => Ok(HashAlgorithm::Bcrypt),
        "scrypt" => Ok(HashAlgorithm::Scrypt),
        other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash {{ hash: {:?} }}", self.hash)
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for HashAlgorithm {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        parse_algorithm_tag(s)
            .map_err(|_| Error::UnsupportedAlgorithm(s.to_owned()))
    }
}

/// Builder for [`struct@Hash`].
#[derive(
    Clone,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
pub struct HashBuilder {
    hash: Option<Vec<u8>>,
    salt: Option<Salt>,
    algorithm: Option<HashAlgorithm>,
}

impl HashBuilder {
    /// Creates a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the hash bytes.
    pub fn hash(mut self, hash: Vec<u8>) -> Self {
        self.hash = Some(hash);
        self
    }

    /// Sets the salt bytes.
    pub fn salt(mut self, salt: Salt) -> Self {
        self.salt = Some(salt);
        self
    }

    /// Sets the algorithm.
    pub fn algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = Some(algorithm);
        self
    }

    /// Consumes the builder and returns the `Hash`, erroring if any
    /// required field is missing.
    pub fn build(self) -> Result<Hash> {
        match (self.hash, self.salt, self.algorithm) {
            (Some(hash), Some(salt), Some(algorithm)) => Ok(Hash {
                hash,
                salt,
                algorithm,
            }),
            _ => Err(Error::InvalidHashString(
                "HashBuilder missing one of: hash, salt, algorithm",
            )),
        }
    }
}
