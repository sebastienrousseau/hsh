// Copyright © 2023-2024 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

use super::hash_algorithm::HashAlgorithm;
use crate::algorithms;
use crate::models::hash_algorithm::HashingAlgorithm;
use algorithms::{argon2i::Argon2i, bcrypt::Bcrypt, scrypt::Scrypt};
use serde::{Deserialize, Serialize};

// use algorithms::{argon2i::Argon2i, bcrypt::Bcrypt, scrypt::Scrypt};
use argon2rs::argon2i_simple;
use base64::{engine::general_purpose, Engine as _};
// use models::{hash::*, hash_algorithm::*};
use scrypt::scrypt;
use std::{fmt, str::FromStr};
use vrd::random::Random;

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
    /// let result = Hash::new_argon2i(password, salt);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Argon2i hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_argon2i(
        password: &str,
        salt: Salt,
    ) -> Result<Self, String> {
        // Convert the Vec<u8> salt to a &str
        let salt_str = std::str::from_utf8(&salt)
            .map_err(|_| "Failed to convert salt to string")?;

        // Perform Argon2i hashing
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
    /// let password = "my_password";
    /// let cost: u32 = 16;
    ///
    /// let result = Hash::new_bcrypt(password, cost);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Bcrypt hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_bcrypt(
        password: &str,
        cost: u32,
    ) -> Result<Self, String> {
        // Perform Bcrypt hashing
        let hashed_password =
            bcrypt::hash(password, cost).map_err(|e| {
                format!("Failed to hash password with Bcrypt: {}", e)
            })?;

        // In Bcrypt, the salt is embedded in the hashed password.
        // So, you can just use an empty salt when building the Hash object.
        let empty_salt = Vec::new();

        HashBuilder::new()
            .hash(hashed_password.as_bytes().to_vec())
            .salt(empty_salt)
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
    /// let result = Hash::new_scrypt(password, salt);
    /// match result {
    ///     Ok(hash) => println!("Successfully created Scrypt hash"),
    ///     Err(e) => println!("An error occurred: {}", e),
    /// }
    /// ```
    pub fn new_scrypt(
        password: &str,
        salt: Salt,
    ) -> Result<Self, String> {
        // Convert the Vec<u8> salt to a &str for hashing
        let salt_str = std::str::from_utf8(&salt)
            .map_err(|_| "Failed to convert salt to string")?;

        // Perform Scrypt hashing using a wrapper function that sets the parameters
        let calculated_hash =
            Scrypt::hash_password(password, salt_str)?;

        // Use the builder pattern to construct the Hash instance
        HashBuilder::new()
            .hash(calculated_hash)
            .salt(salt)
            .algorithm(HashAlgorithm::Scrypt)
            .build()
    }

    /// A function that returns the hash algorithm used by the hash map.
    pub fn algorithm(&self) -> HashAlgorithm {
        self.algorithm
    }

    /// A function that creates a new hash object from a hash value and a hash algorithm.
    pub fn from_hash(hash: &[u8], algo: &str) -> Result<Self, String> {
        let algorithm = match algo {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }?;

        Ok(Hash {
            salt: Vec::new(),
            hash: hash.to_vec(),
            algorithm,
        })
    }

    /// A function that creates a new hash object from a hash string in the format algorithm$salt$hash.
    pub fn from_string(hash_str: &str) -> Result<Self, String> {
        // Split the hash string into six parts, using the `$` character as the delimiter.
        let parts: Vec<&str> = hash_str.split('$').collect();

        // If the hash string does not contain six parts, return an error.
        if parts.len() != 6 {
            return Err(String::from("Invalid hash string"));
        }

        // Parse the algorithm from the first part of the hash string.
        let algorithm = Self::parse_algorithm(hash_str)?;

        // Parse the salt from the second, third, fourth, and fifth parts of the hash string.
        let salt = format!(
            "${}${}${}${}",
            parts[1], parts[2], parts[3], parts[4]
        );

        // Decode the hash bytes from the sixth part of the hash string.
        let hash_bytes =
            general_purpose::STANDARD.decode(parts[5]).map_err(
                |_| format!("Failed to decode base64: {}", parts[5]),
            )?;

        // Create the `Hash` object and return it.
        Ok(Hash {
            salt: salt.into_bytes(),
            hash: hash_bytes,
            algorithm,
        })
    }

    /// A function that generates a hash value for a password using the specified hash algorithm.
    /// The function takes three arguments:
    ///
    /// - password: The password to be hashed.
    /// - salt: A random string used to make the hash value unique.
    /// - algo: The name of the hash algorithm to use.
    ///
    /// The function returns a `Result` object containing the hash value if successful, or an error message if unsuccessful.
    pub fn generate_hash(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Vec<u8>, String> {
        match algo {
            "argon2i" => Argon2i::hash_password(password, salt),
            "bcrypt" => Bcrypt::hash_password(password, salt),
            "scrypt" => Scrypt::hash_password(password, salt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }
    }

    /// A function that generates a random string of the specified length.
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

    /// A function that generates a random salt for a password using the specified hash algorithm.
    pub fn generate_salt(algo: &str) -> Result<String, String> {
        let mut rng = Random::default();
        match algo {
            "argon2i" => Ok(Self::generate_random_string(16)),
            "bcrypt" => {
                let salt: Vec<u8> = rng.bytes(16);
                let salt_array: [u8; 16] =
                    salt.try_into().map_err(|_| {
                        "Error: failed to convert salt to an array"
                    })?;
                Ok(general_purpose::STANDARD.encode(&salt_array[..]))
            }
            "scrypt" => {
                let salt: Vec<u8> = rng.bytes(32);
                let salt_array: [u8; 32] =
                    salt.try_into().map_err(|_| {
                        "Error: failed to convert salt to an array"
                    })?;
                Ok(general_purpose::STANDARD.encode(&salt_array[..]))
            }
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }
    }

    /// A function that returns the hash value of a hash object.
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    /// A function that returns the length of the hash value of a hash object.
    pub fn hash_length(&self) -> usize {
        self.hash.len()
    }

    /// A function that creates a new hash object from a password, salt, and hash algorithm.
    pub fn new(
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<Self, String> {
        // Enforce a minimum password length of 8 characters.
        if password.len() < 8 {
            return Err(String::from("Password is too short. It must be at least 8 characters."));
        }
        let hash = Self::generate_hash(password, salt, algo)?;

        let algorithm = match algo {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => Err(format!("Unsupported hash algorithm: {}", algo)),
        }?;

        Ok(Self {
            hash,
            salt: salt.as_bytes().to_vec(),
            algorithm,
        })
    }

    /// A function that parses a JSON string into a hash object.
    pub fn parse(
        input: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let hash: Hash = serde_json::from_str(input)?;
        Ok(hash)
    }

    /// A function that parses a hash string into a hash algorithm.
    pub fn parse_algorithm(
        hash_str: &str,
    ) -> Result<HashAlgorithm, String> {
        let parts: Vec<&str> = hash_str.split('$').collect();
        if parts.len() < 2 {
            return Err(String::from("Invalid hash string"));
        }
        match parts[1] {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => {
                Err(format!("Unsupported hash algorithm: {}", parts[1]))
            }
        }
    }

    /// A function that returns the salt used to hash a password.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// A function that sets the hash value of a hash object.
    pub fn set_hash(&mut self, hash: &[u8]) {
        self.hash = hash.to_vec();
    }

    /// A function that sets the password of a hash object.
    pub fn set_password(
        &mut self,
        password: &str,
        salt: &str,
        algo: &str,
    ) -> Result<(), String> {
        self.hash = Self::generate_hash(password, salt, algo)?;
        Ok(())
    }

    /// A function that sets the salt of a hash object.
    pub fn set_salt(&mut self, salt: &[u8]) {
        self.salt = salt.to_vec();
    }

    /// A function that converts a hash object to a string representation.
    pub fn to_string_representation(&self) -> String {
        let hash_str = self
            .hash
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<String>>()
            .join("");

        format!("{}:{}", String::from_utf8_lossy(&self.salt), hash_str)
    }

    /// A function that verifies a password against a hash object.
    pub fn verify(&self, password: &str) -> Result<bool, &'static str> {
        let salt = std::str::from_utf8(&self.salt)
            .map_err(|_| "Failed to convert salt to string")?;

        match self.algorithm {
            HashAlgorithm::Argon2i => {
                // Hash the password once
                let calculated_hash =
                    argon2i_simple(password, salt).to_vec();

                // Debugging information
                println!("Algorithm: Argon2i");
                println!(
                    "Provided password for verification: {}",
                    password
                );
                println!("Salt used for verification: {}", salt);
                println!("Calculated Hash: {:?}", calculated_hash);
                println!("Stored Hash: {:?}", self.hash);

                // Perform the verification
                Ok(calculated_hash == self.hash)
            }
            HashAlgorithm::Bcrypt => {
                // Debugging information
                println!("Algorithm: Bcrypt");
                println!(
                    "Provided password for verification: {}",
                    password
                );

                let hash_str = std::str::from_utf8(&self.hash)
                    .map_err(|_| "Failed to convert hash to string")?;
                bcrypt::verify(password, hash_str)
                    .map_err(|_| "Failed to verify Bcrypt password")
            }
            HashAlgorithm::Scrypt => {
                // Debugging information
                println!("Algorithm: Scrypt");
                println!(
                    "Provided password for verification: {}",
                    password
                );
                println!("Salt used for verification: {}", salt);

                let scrypt_params = scrypt::Params::new(14, 8, 1, 64)
                    .map_err(|_| {
                    "Failed to create Scrypt params"
                })?;
                let mut output = [0u8; 64];
                match scrypt(
                    password.as_bytes(),
                    salt.as_bytes(),
                    &scrypt_params,
                    &mut output,
                ) {
                    Ok(_) => {
                        println!(
                            "Calculated Hash: {:?}",
                            output.to_vec()
                        );
                        println!("Stored Hash: {:?}", self.hash);
                        Ok(output.to_vec() == self.hash)
                    }
                    Err(_) => Err("Scrypt hashing failed"),
                }
            }
        }
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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let algorithm = match s {
            "argon2i" => HashAlgorithm::Argon2i,
            "bcrypt" => HashAlgorithm::Bcrypt,
            "scrypt" => HashAlgorithm::Scrypt,
            _ => return Err(String::from("Invalid hash algorithm")),
        };
        Ok(algorithm)
    }
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
        if let (Some(hash), Some(salt), Some(algorithm)) =
            (self.hash, self.salt, self.algorithm)
        {
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
