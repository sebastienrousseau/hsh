// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Core `Hash` type for storing and verifying password hashes.
//!
//! Built on the RustCrypto stack (Phase 1):
//! - Argon2 family via the [`argon2`] crate, with Argon2id as the
//!   recommended default per RFC 9106 §4.
//! - Bcrypt with the explicit 72-byte safety rail (CVE-2025-22228 class).
//! - Scrypt with configurable parameters; default is the OWASP-2025
//!   minimum (`N = 2^17`).
//! - Salts generated from [`getrandom`] (OS CSPRNG).
//! - Verification is constant-time everywhere via [`subtle`].
//! - Secret material is zeroed on drop via [`zeroize`].

use super::hash_algorithm::HashAlgorithm;
use crate::algorithms::{
    argon2id::{self as a2, Argon2d, Argon2i, Argon2id},
    bcrypt::Bcrypt,
    pbkdf2::{Pbkdf2, Pbkdf2Params},
    scrypt::{Scrypt, ScryptParams},
};
use crate::error::{Error, Result};
use crate::models::hash_algorithm::HashingAlgorithm;
use ::argon2::Algorithm as Argon2Algorithm;
use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use subtle::ConstantTimeEq;
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
    /// The hash algorithm used. Carries no secret, so skipped from
    /// the zeroize derive to avoid requiring a `Zeroize` impl on
    /// the enum.
    #[zeroize(skip)]
    algorithm: HashAlgorithm,
}

impl Hash {
    /// Creates a new `Hash` using **Argon2id** — the recommended variant.
    ///
    /// # Example
    ///
    /// ```
    /// use hsh::models::hash::{Hash, Salt};
    ///
    /// let salt: Salt = vec![b'a'; 16];
    /// let _ = Hash::new_argon2id("correct horse", salt);
    /// ```
    pub fn new_argon2id(password: &str, salt: Salt) -> Result<Self> {
        let salt_str = std::str::from_utf8(&salt)?;
        let calculated = Argon2id::hash_password(password, salt_str)?;
        Ok(Self {
            hash: calculated,
            salt,
            algorithm: HashAlgorithm::Argon2id,
        })
    }

    /// Creates a new `Hash` using **Argon2i**.
    ///
    /// Verify-only for legacy hashes — Argon2i is **not** recommended for
    /// new password hashes. Prefer [`Hash::new_argon2id`].
    #[deprecated(
        since = "0.0.9",
        note = "Argon2i is verify-only — use Hash::new_argon2id for new hashes."
    )]
    pub fn new_argon2i(password: &str, salt: Salt) -> Result<Self> {
        let salt_str = std::str::from_utf8(&salt)?;
        let calculated = Argon2i::hash_password(password, salt_str)?;
        Ok(Self {
            hash: calculated,
            salt,
            algorithm: HashAlgorithm::Argon2i,
        })
    }

    /// Creates a new `Hash` using Bcrypt at the given `cost`.
    ///
    /// Returns [`Error::InvalidPassword`] if the password exceeds 72
    /// bytes — use [`crate::algorithms::bcrypt::BcryptParams::with_prehash`]
    /// for explicit handling of longer inputs.
    pub fn new_bcrypt(password: &str, cost: u32) -> Result<Self> {
        use crate::algorithms::bcrypt::{
            BcryptParams, PrehashAlgorithm,
        };
        let params = BcryptParams {
            cost,
            prehash: PrehashAlgorithm::None,
        };
        let hashed = Bcrypt::hash_with(password, params)?;
        Ok(Self {
            hash: hashed,
            salt: Vec::new(),
            algorithm: HashAlgorithm::Bcrypt,
        })
    }

    /// Creates a new `Hash` using Scrypt with OWASP-2025 default params.
    pub fn new_scrypt(password: &str, salt: Salt) -> Result<Self> {
        let salt_str = std::str::from_utf8(&salt)?;
        let calculated = Scrypt::hash_password(password, salt_str)?;
        Ok(Self {
            hash: calculated,
            salt,
            algorithm: HashAlgorithm::Scrypt,
        })
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

    /// Parses the legacy `$algo$...$hash` serialized form.
    ///
    /// **Not PHC-compliant** — Phase 1C (issue #159) replaces this with
    /// `password_hash::PasswordHashString`.
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

    /// Generates a raw hash for `password` with the given `salt` and
    /// algorithm tag. Returns the raw bytes only; for the storable form
    /// build a `Hash` and call [`Hash::to_string_representation`] or
    /// (Phase 1C) serialize as PHC.
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Vec<u8>> {
        match algo {
            "argon2id" => Argon2id::hash_password(password, salt),
            "argon2i" => Argon2i::hash_password(password, salt),
            "argon2d" => Argon2d::hash_password(password, salt),
            "bcrypt" => Bcrypt::hash_password(password, salt),
            "scrypt" => Scrypt::hash_password(password, salt),
            "pbkdf2" | "pbkdf2-sha256" => {
                Pbkdf2::hash_password(password, salt)
            }
            other => Err(Error::UnsupportedAlgorithm(other.to_owned())),
        }
    }

    /// Generates a random alphanumeric string of length `len` from the OS
    /// CSPRNG. Suitable for human-readable Argon2 salts.
    pub fn generate_random_string(len: usize) -> Result<String> {
        const CHARS: &[u8] =
            b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

        let mut raw = vec![0u8; len];
        getrandom::getrandom(&mut raw).map_err(|e| {
            Error::Hashing(format!("OS RNG failed: {e}"))
        })?;

        let s: String = raw
            .into_iter()
            .map(|b| CHARS[usize::from(b) % CHARS.len()] as char)
            .collect();
        Ok(s)
    }

    /// Generates a salt suitable for the named algorithm using the OS
    /// CSPRNG. Returns a UTF-8 string ready for storage.
    pub fn generate_salt(algo: &str) -> Result<String> {
        match algo {
            "argon2id" | "argon2i" | "argon2d" => {
                Self::generate_random_string(16)
            }
            "bcrypt" => {
                let mut raw = [0u8; 16];
                getrandom::getrandom(&mut raw).map_err(|e| {
                    Error::Hashing(format!("OS RNG failed: {e}"))
                })?;
                Ok(general_purpose::STANDARD.encode(raw))
            }
            "scrypt" => {
                let mut raw = [0u8; 32];
                getrandom::getrandom(&mut raw).map_err(|e| {
                    Error::Hashing(format!("OS RNG failed: {e}"))
                })?;
                Ok(general_purpose::STANDARD.encode(raw))
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
    ///
    /// Recognised tags: `"argon2id"` (recommended), `"argon2i"`,
    /// `"argon2d"`, `"bcrypt"`, `"scrypt"`.
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

    /// Sets the hash bytes, zeroing the previous buffer first.
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

    /// Sets the salt bytes, zeroing the previous buffer first.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt.zeroize();
        self.salt = salt.to_vec();
    }

    /// Returns a non-PHC `salt:hex` debug string.
    pub fn to_string_representation(&self) -> String {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<String>>()
            .join("");
        format!("{}:{}", String::from_utf8_lossy(&self.salt), hash_str)
    }

    /// Verifies `password` against this hash.
    ///
    /// **Constant-time:** the byte comparison uses
    /// [`subtle::ConstantTimeEq`]. The bcrypt path delegates to the
    /// `bcrypt` crate, which also uses `subtle` internally.
    ///
    /// Returns `Ok(true)` for a match, `Ok(false)` for a mismatch, or an
    /// [`Error`] if the stored material is malformed.
    pub fn verify(&self, password: &str) -> Result<bool> {
        let salt = std::str::from_utf8(&self.salt)?;

        match self.algorithm {
            HashAlgorithm::Argon2id => a2::verify(
                Argon2Algorithm::Argon2id,
                a2::owasp_minimum_2025(),
                password,
                salt,
                &self.hash,
            ),
            HashAlgorithm::Argon2i => a2::verify(
                Argon2Algorithm::Argon2i,
                a2::owasp_minimum_2025(),
                password,
                salt,
                &self.hash,
            ),
            HashAlgorithm::Argon2d => a2::verify(
                Argon2Algorithm::Argon2d,
                a2::owasp_minimum_2025(),
                password,
                salt,
                &self.hash,
            ),
            HashAlgorithm::Bcrypt => {
                use crate::algorithms::bcrypt::PrehashAlgorithm;
                let stored_str = std::str::from_utf8(&self.hash)?;
                Bcrypt::verify(
                    password,
                    stored_str,
                    PrehashAlgorithm::None,
                )
            }
            HashAlgorithm::Scrypt => {
                let calculated = Scrypt::hash_with(
                    password,
                    salt,
                    ScryptParams::default(),
                )?;
                let ok = bool::from(calculated.ct_eq(&self.hash));
                let mut tmp = calculated;
                tmp.zeroize();
                Ok(ok)
            }
            HashAlgorithm::Pbkdf2 => {
                let calculated = Pbkdf2::hash_with(
                    password,
                    salt,
                    Pbkdf2Params::default(),
                )?;
                let ok = bool::from(calculated.ct_eq(&self.hash));
                let mut tmp = calculated;
                tmp.zeroize();
                Ok(ok)
            }
        }
    }
}

fn parse_algorithm_tag(algo: &str) -> Result<HashAlgorithm> {
    match algo {
        "pbkdf2" | "pbkdf2-sha256" | "pbkdf2-sha512" => {
            Ok(HashAlgorithm::Pbkdf2)
        }
        "argon2id" => Ok(HashAlgorithm::Argon2id),
        "argon2i" => Ok(HashAlgorithm::Argon2i),
        "argon2d" => Ok(HashAlgorithm::Argon2d),
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
        write!(f, "{self:?}")
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
