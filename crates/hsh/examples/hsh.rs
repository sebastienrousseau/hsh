// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Demonstrates how to create and verify password hashes with Argon2id,
//! bcrypt, and scrypt using the v0.0.9 API.

use hsh::models::{hash::Hash, hash_algorithm::HashAlgorithm};
use std::str::FromStr;

/// Creates one hash per algorithm, verifies it, then re-hashes with a new
/// password and verifies again.
fn create_and_verify_hash() {
    let salt = "salt12345678abcd"; // 16 bytes for Argon2/scrypt

    let hash_argon2id =
        Hash::new("password", salt, "argon2id").unwrap();
    let hash_bcrypt = Hash::new_bcrypt("password", 4).unwrap();
    let hash_scrypt = Hash::new("password", salt, "scrypt").unwrap();

    verify_password(&hash_argon2id, "password", "Argon2id");
    verify_password(&hash_bcrypt, "password", "Bcrypt");
    verify_password(&hash_scrypt, "password", "Scrypt");

    let mut new_hash_argon2id = hash_argon2id.clone();
    new_hash_argon2id
        .set_password("new_password", salt, "argon2id")
        .unwrap();

    let mut new_hash_scrypt = hash_scrypt.clone();
    new_hash_scrypt
        .set_password("new_password", salt, "scrypt")
        .unwrap();

    verify_password(&new_hash_argon2id, "new_password", "Argon2id");
    verify_password(&new_hash_scrypt, "new_password", "Scrypt");
}

fn verify_password(hash: &Hash, password: &str, algorithm: &str) {
    println!("\n===[ Verifying password with {algorithm} ]===\n");

    match hash.verify(password) {
        Ok(true) => {
            println!("Algorithm: {algorithm}");
            println!("Salt: {}", String::from_utf8_lossy(hash.salt()));
            println!("Hash length: {} bytes", hash.hash_length());
            println!("✅ Verification succeeded.");
        }
        Ok(false) => {
            println!("Algorithm: {algorithm}");
            println!("❌ Verification rejected the candidate.");
        }
        Err(e) => {
            eprintln!(
                "Algorithm: {algorithm} — verification error: {e}"
            );
        }
    }

    println!("\n==================================================\n");
}

fn parse_and_display_hash() {
    println!("\n===[ Parsing hash algorithms ]===\n");

    let parsed_argon2id = HashAlgorithm::from_str("argon2id").unwrap();
    let parsed_argon2i = HashAlgorithm::from_str("argon2i").unwrap();
    let parsed_bcrypt = HashAlgorithm::from_str("bcrypt").unwrap();
    let parsed_scrypt = HashAlgorithm::from_str("scrypt").unwrap();

    println!("🦀 Argon2id: {parsed_argon2id}");
    println!(
        "🦀 Argon2i:  {parsed_argon2i} (verify-only for legacy hashes)"
    );
    println!("🦀 Bcrypt:   {parsed_bcrypt}");
    println!("🦀 Scrypt:   {parsed_scrypt}");

    println!("\n===[ Hash to string ]===\n");

    let salt = "salt12345678abcd";
    let argon2id_hash = Hash::new("password", salt, "argon2id");
    let bcrypt_hash = Hash::new_bcrypt("password", 4);
    let scrypt_hash = Hash::new("password", salt, "scrypt");

    let argon2id_repr = match &argon2id_hash {
        Ok(h) => h.to_string_representation(),
        Err(e) => format!("Error: {e}"),
    };
    let bcrypt_repr = match &bcrypt_hash {
        Ok(h) => h.to_string_representation(),
        Err(e) => format!("Error: {e}"),
    };
    let scrypt_repr = match &scrypt_hash {
        Ok(h) => h.to_string_representation(),
        Err(e) => format!("Error: {e}"),
    };

    println!("🦀 Argon2id repr: {argon2id_repr}");
    println!("🦀 Bcrypt repr:   {bcrypt_repr}");
    println!("🦀 Scrypt repr:   {scrypt_repr}");

    println!("\n========================================\n");
}

fn main() {
    create_and_verify_hash();
    parse_and_display_hash();
}
