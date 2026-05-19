#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(deprecated)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Targeted unit-coverage for the per-algorithm wrappers — the
//! `HashingAlgorithm` trait impls for Argon2i / Argon2d / Bcrypt /
//! Scrypt / Pbkdf2, plus the error-path branches that only fire on
//! invalid parameters.

use hsh::algorithms::argon2id::{Argon2d, Argon2i, Argon2id};
use hsh::algorithms::bcrypt::{Bcrypt, BcryptParams};
use hsh::algorithms::pbkdf2::{Pbkdf2, Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::{Scrypt, ScryptParams};
use hsh::models::hash_algorithm::HashingAlgorithm;
use hsh::Error;

// ---------------------------------------------------------------------------
// HashingAlgorithm trait impls — every wrapper's hash_password entry point.
// ---------------------------------------------------------------------------

#[test]
fn argon2id_hash_password_via_trait() {
    let out = Argon2id::hash_password("hunter2!", "abcdefghijklmnop").unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2i_hash_password_via_trait() {
    let out = Argon2i::hash_password("hunter2!", "abcdefghijklmnop").unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn argon2d_hash_password_via_trait() {
    let out = Argon2d::hash_password("hunter2!", "abcdefghijklmnop").unwrap();
    assert_eq!(out.len(), 32);
}

#[test]
fn bcrypt_hash_password_via_trait() {
    let out = Bcrypt::hash_password("hunter2!", "ignored").unwrap();
    // Bcrypt produces an MCF string in bytes form.
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("$2"));
}

#[test]
fn scrypt_hash_password_via_trait() {
    let out = Scrypt::hash_password("hunter2!", "abcdefghijklmnopabcdefghijklmnop").unwrap();
    assert!(!out.is_empty());
}

#[test]
fn pbkdf2_hash_password_via_trait() {
    let out =
        Pbkdf2::hash_password("hunter2!", "abcdefghijklmnop").unwrap();
    assert_eq!(out.len(), 32);
}

// ---------------------------------------------------------------------------
// PBKDF2 — explicit param validation paths
// ---------------------------------------------------------------------------

#[test]
fn pbkdf2_rejects_zero_iterations() {
    let bad = Pbkdf2Params {
        prf: Prf::Sha256,
        iterations: 0,
        dk_len: 32,
    };
    let err = Pbkdf2::hash_with(b"pw", b"abcdefghijklmnop", bad).unwrap_err();
    assert!(matches!(err, Error::InvalidParameter(_)));
}

#[test]
fn pbkdf2_rejects_zero_dk_len() {
    let bad = Pbkdf2Params {
        prf: Prf::Sha256,
        iterations: 1,
        dk_len: 0,
    };
    let err = Pbkdf2::hash_with(b"pw", b"abcdefghijklmnop", bad).unwrap_err();
    assert!(matches!(err, Error::InvalidParameter(_)));
}

#[test]
fn pbkdf2_sha512_prf_path() {
    let params = Pbkdf2Params {
        prf: Prf::Sha512,
        iterations: 1,
        dk_len: 64,
    };
    let out =
        Pbkdf2::hash_with(b"pw", b"abcdefghijklmnop", params).unwrap();
    assert_eq!(out.len(), 64);
}

#[test]
fn pbkdf2_round_trip_is_deterministic() {
    let params = Pbkdf2Params {
        prf: Prf::Sha256,
        iterations: 10,
        dk_len: 32,
    };
    let a = Pbkdf2::hash_with(b"pw", b"sssssssssssssss1", params).unwrap();
    let b = Pbkdf2::hash_with(b"pw", b"sssssssssssssss1", params).unwrap();
    assert_eq!(a, b);
}

#[test]
fn pbkdf2_different_prfs_yield_different_outputs() {
    let sha256 = Pbkdf2::hash_with(
        b"pw",
        b"abcdefghijklmnop",
        Pbkdf2Params {
            prf: Prf::Sha256,
            iterations: 1,
            dk_len: 32,
        },
    )
    .unwrap();
    let sha512 = Pbkdf2::hash_with(
        b"pw",
        b"abcdefghijklmnop",
        Pbkdf2Params {
            prf: Prf::Sha512,
            iterations: 1,
            dk_len: 32,
        },
    )
    .unwrap();
    assert_ne!(sha256, sha512);
}

// ---------------------------------------------------------------------------
// Scrypt — to_native + invalid-param branches
// ---------------------------------------------------------------------------

#[test]
fn scrypt_to_native_rejects_invalid_combination() {
    // scrypt::Params accepts log_n == 0 but rejects degenerate r/p
    // combinations (r * p > 0x40000000).
    let bad = ScryptParams {
        log_n: 1,
        r: u32::MAX,
        p: u32::MAX,
        dk_len: 32,
    };
    let err = bad.to_native().unwrap_err();
    assert!(matches!(err, Error::InvalidParameter(_)));
}

#[test]
fn scrypt_to_native_accepts_default() {
    let p = ScryptParams::default();
    assert!(p.to_native().is_ok());
}

#[test]
fn scrypt_hash_with_round_trip_is_deterministic() {
    let params = ScryptParams {
        log_n: 8,
        r: 8,
        p: 1,
        dk_len: 32,
    };
    let a =
        Scrypt::hash_with("pw", "abcdefghijklmnop", params).unwrap();
    let b =
        Scrypt::hash_with("pw", "abcdefghijklmnop", params).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Bcrypt — pre-hash adapter + safety rail
// ---------------------------------------------------------------------------

#[test]
fn bcrypt_with_prehash_sha256_accepts_long_input() {
    use hsh::algorithms::bcrypt::PrehashAlgorithm;
    let params =
        BcryptParams::new(4).with_prehash(PrehashAlgorithm::Sha256);
    let long = "x".repeat(200);
    let out = Bcrypt::hash_with(&long, params).unwrap();
    let s = std::str::from_utf8(&out).unwrap();
    assert!(s.starts_with("$2"));
}

#[test]
fn bcrypt_rejects_oversize_without_prehash() {
    let params = BcryptParams::new(4);
    let long = "x".repeat(73);
    let err = Bcrypt::hash_with(&long, params).unwrap_err();
    assert!(matches!(err, Error::InvalidPassword(_)));
}

#[test]
fn bcrypt_verify_rejects_wrong_password() {
    use hsh::algorithms::bcrypt::PrehashAlgorithm;
    let stored = Bcrypt::hash_with("real", BcryptParams::new(4)).unwrap();
    let s = std::str::from_utf8(&stored).unwrap();
    let ok =
        Bcrypt::verify("wrong", s, PrehashAlgorithm::None).unwrap();
    assert!(!ok);
}

#[test]
fn bcrypt_verify_accepts_correct_password() {
    use hsh::algorithms::bcrypt::PrehashAlgorithm;
    let stored = Bcrypt::hash_with("real", BcryptParams::new(4)).unwrap();
    let s = std::str::from_utf8(&stored).unwrap();
    let ok =
        Bcrypt::verify("real", s, PrehashAlgorithm::None).unwrap();
    assert!(ok);
}

// ---------------------------------------------------------------------------
// Argon2 verify path — direct verify() call covering the constant-time
// compare + error branches.
// ---------------------------------------------------------------------------

#[test]
fn argon2id_verify_matches_when_inputs_agree() {
    use hsh::algorithms::argon2id::{owasp_minimum_2025, verify};
    use argon2::Algorithm;

    let salt = "abcdefghijklmnop";
    let pw = "secret password";
    let stored =
        Argon2id::hash_password(pw, salt).unwrap();
    let ok = verify(
        Algorithm::Argon2id,
        owasp_minimum_2025(),
        pw,
        salt,
        &stored,
    )
    .unwrap();
    assert!(ok);
}

#[test]
fn argon2id_verify_rejects_wrong_password() {
    use hsh::algorithms::argon2id::{owasp_minimum_2025, verify};
    use argon2::Algorithm;

    let salt = "abcdefghijklmnop";
    let stored =
        Argon2id::hash_password("real", salt).unwrap();
    let ok = verify(
        Algorithm::Argon2id,
        owasp_minimum_2025(),
        "wrong",
        salt,
        &stored,
    )
    .unwrap();
    assert!(!ok);
}

#[test]
fn argon2id_verify_returns_false_on_size_mismatch() {
    use hsh::algorithms::argon2id::{owasp_minimum_2025, verify};
    use argon2::Algorithm;

    // Stored hash with wrong length triggers the size-mismatch
    // early-return (Ok(false), not Err).
    let ok = verify(
        Algorithm::Argon2id,
        owasp_minimum_2025(),
        "pw",
        "abcdefghijklmnop",
        b"too short",
    )
    .unwrap();
    assert!(!ok);
}
