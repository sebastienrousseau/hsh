// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Using the Hash (HSH) library

use hsh::{
    models::{hash::Hash, hash_algorithm::HashAlgorithm},
    new_hash,
};
use std::str::FromStr;

/// This function demonstrates how to create and verify password hashes using Argon2i, Bcrypt, and Scrypt algorithms.
///
/// # Example
///
/// ```rust
/// use hsh::models::{hash::Hash, salt::Salt};
///
/// // Function to create and verify hash
/// fn create_and_verify_hash() {
///     // Create new hashes for Argon2i, Bcrypt, and Scrypt
///     let password = "password";
///     let salt_argon2i: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
///     let salt_scrypt: Salt = vec![10, 11, 12, 13, 14, 15, 16, 17, 18, 19];
///     let cost_bcrypt = 16;
///
///     let hash_argon2i = Hash::new_argon2i(password, salt_argon2i).unwrap();
///     let hash_bcrypt = Hash::new_bcrypt(password, cost_bcrypt).unwrap();
///     let hash_scrypt = Hash::new_scrypt(password, salt_scrypt).unwrap();
///
///     // Verify these hashes
///     verify_password(&hash_argon2i, "password", "Argon2i");
///     verify_password(&hash_bcrypt, "password", "BCrypt");
///     verify_password(&hash_scrypt, "password", "Scrypt");
///
///     // ... (the rest of the function)
/// }
/// ```
///
/// Note: This is a simplified example, and in a real-world application, you should handle errors and edge cases more carefully.
fn create_and_verify_hash() {
    // Create new hashes for Argon2i, Bcrypt, and Scrypt
    let hash_argon2i =
        Hash::new_argon2i("password", "salt1234".into()).unwrap();
    let hash_bcrypt = Hash::new_bcrypt("password", 16).unwrap();
    let hash_scrypt =
        Hash::new_scrypt("password", "salt1234".into()).unwrap();

    // Verify these hashes
    verify_password(&hash_argon2i, "password", "Argon2i");
    verify_password(&hash_bcrypt, "password", "BCrypt");
    verify_password(&hash_scrypt, "password", "Scrypt");

    // Update the hashes
    let mut new_hash_argon2i = hash_argon2i.clone();
    new_hash_argon2i
        .set_password("new_password", "salt1234", "argon2i")
        .unwrap();

    let mut new_hash_bcrypt = hash_bcrypt.clone();
    new_hash_bcrypt
        .set_password("new_password", "salt1234", "bcrypt")
        .unwrap();

    let mut new_hash_scrypt = hash_scrypt.clone();
    new_hash_scrypt
        .set_password("new_password", "salt1234", "scrypt")
        .unwrap();

    // Verify the updated hashes
    verify_password(&new_hash_argon2i, "new_password", "Argon2i");
    verify_password(&new_hash_bcrypt, "new_password", "BCrypt");
    verify_password(&new_hash_scrypt, "new_password", "Scrypt");
}

// Function to verify the password
fn verify_password(hash: &Hash, password: &str, algorithm: &str) {
    // Print header
    println!(
        "\n===[ Verifying Password with {} Algorithm ]===\n",
        algorithm
    );

    let is_valid = hash.verify(password);
    match is_valid {
        Ok(valid) => {
            println!("Algorithm: {}", algorithm);
            println!(
                "Provided password for verification: {}",
                password
            );
            println!(
                "Salt used for verification: {}",
                String::from_utf8_lossy(hash.salt())
            );
            println!(
                "🦀 Password verification result for {}: ✅ {:?}",
                algorithm, valid
            );
        }
        Err(e) => {
            eprintln!(
                "🦀 Error during password verification for {}: ❌ {}",
                algorithm, e
            );
        }
    }

    // Print footer
    println!("\n==================================================\n");
}

// Function to parse and display hash algorithms and their string representations
fn parse_and_display_hash() {
    // Print header for parsing algorithms
    println!("\n===[ Parsing Hash Algorithms ]===\n");

    let parsed_argon2i = HashAlgorithm::from_str("argon2i").unwrap();
    let parsed_bcrypt = HashAlgorithm::from_str("bcrypt").unwrap();
    let parsed_scrypt = HashAlgorithm::from_str("scrypt").unwrap();

    println!("🦀 Parsed Argon2i hash algorithm: {}", parsed_argon2i);
    println!("🦀 Parsed Bcrypt hash algorithm: {}", parsed_bcrypt);
    println!("🦀 Parsed Scrypt hash algorithm: {}", parsed_scrypt);

    // Print footer for parsing algorithms
    println!("\n======================================\n");

    // Print header for hash to string conversion
    println!("\n===[ Hash to String Conversion ]===\n");

    let argon2i_hash = new_hash!("password", "salt12345", "argon2i");
    let bcrypt_hash = new_hash!("password", "salt12345", "bcrypt");
    let scrypt_hash = new_hash!("password", "salt12345", "scrypt");

    let argon2i_hash_string = match argon2i_hash {
        Ok(hash) => hash.to_string_representation(),
        Err(e) => format!("Error: {}", e),
    };
    let bcrypt_hash_string = match bcrypt_hash {
        Ok(hash) => hash.to_string_representation(),
        Err(e) => format!("Error: {}", e),
    };
    let scrypt_hash_string = match scrypt_hash {
        Ok(hash) => hash.to_string_representation(),
        Err(e) => format!("Error: {}", e),
    };

    println!("🦀 Argon2i Hash to a string: {}", argon2i_hash_string);
    println!("🦀 Bcrypt Hash to a string: {}", bcrypt_hash_string);
    println!("🦀 Scrypt Hash to a string: {}", scrypt_hash_string);

    // Print footer for hash to string conversion
    println!("\n========================================\n");
}

// Main function
fn main() {
    create_and_verify_hash();
    parse_and_display_hash();
}
