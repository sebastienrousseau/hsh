// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Using the Hash (HSH) library

use std::str::FromStr;
use hsh::{models::{hash::Hash, hash_algorithm::HashAlgorithm}, new_hash};

fn create_new_hash(password: &str, salt: &str, algorithm: &str) -> Result<Hash, String> {
    let hash = Hash::new(password, salt, algorithm)?;
    println!("Debug: Salt used for new hash: {:?}", String::from_utf8_lossy(hash.salt()));
    Ok(hash)
}

fn create_and_verify_hash() {
    let hash_argon2i = create_new_hash("password", "salt1234", "argon2i").unwrap();
    let hash_bcrypt = create_new_hash("password", "salt1234", "bcrypt").unwrap();
    let hash_scrypt = create_new_hash("password", "salt1234", "scrypt").unwrap();

    // Verify the newly created hashes
    verify_password(&hash_argon2i, "password", "Argon2i");
    verify_password(&hash_bcrypt, "password", "BCrypt");
    verify_password(&hash_scrypt, "password", "Scrypt");

    let mut new_hash_argon2i = hash_argon2i.clone();
    new_hash_argon2i.set_password("new_password", "salt1234", "argon2i").unwrap();

    let mut new_hash_bcrypt = hash_bcrypt.clone();
    new_hash_bcrypt.set_password("new_password", "salt1234", "bcrypt").unwrap();

    let mut new_hash_scrypt = hash_scrypt.clone();
    new_hash_scrypt.set_password("new_password", "salt1234", "scrypt").unwrap();

    // Verify the updated hashes
    verify_password(&new_hash_argon2i, "new_password", "Argon2i");
    verify_password(&new_hash_bcrypt, "new_password", "BCrypt");
    verify_password(&new_hash_scrypt, "new_password", "Scrypt");
}

fn verify_password(hash: &Hash, password: &str, algorithm: &str) {
    let is_valid = hash.verify(password);
    match is_valid {
        Ok(valid) => {
            println!("🦀 Password verification result for {}: ✅ {:?}", algorithm, valid);
        },
        Err(e) => {
            eprintln!("🦀 Error during password verification for {}: ❌ {}", algorithm, e);
        }
    }
}

fn parse_and_display_hash() {
    let parsed_argon2i = HashAlgorithm::from_str("argon2i").unwrap();
    let parsed_bcrypt = HashAlgorithm::from_str("bcrypt").unwrap();
    let parsed_scrypt = HashAlgorithm::from_str("scrypt").unwrap();

    println!("🦀 Parsed Argon2i hash algorithm: {}", parsed_argon2i);
    println!("🦀 Parsed Bcrypt hash algorithm: {}", parsed_bcrypt);
    println!("🦀 Parsed Scrypt hash algorithm: {}", parsed_scrypt);

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
}


fn main() {
    create_and_verify_hash();
    parse_and_display_hash();
}
