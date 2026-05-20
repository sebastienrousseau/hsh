#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Branch-coverage tests for `crates/hsh/src/api.rs` — the error
//! paths, malformed-input handling, Argon2i / Argon2d verify, PBKDF2
//! PHC parsing, and the bcrypt non-UTF-8 input rejection. The happy
//! paths are covered by `test_api.rs` / `test_pepper.rs` / `test_pbkdf2.rs`;
//! this file pins the *unhappy* branches.

use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{api, Error, Outcome};

fn fast_test_policy(primary: PrimaryAlgorithm) -> Policy {
    PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
        .primary(primary)
        .argon2(argon2::Params::new(8, 1, 1, Some(32)).unwrap())
        .bcrypt(hsh::algorithms::bcrypt::BcryptParams::new(4))
        .scrypt(hsh::algorithms::scrypt::ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        })
        .pbkdf2(Pbkdf2Params {
            prf: Prf::Sha256,
            iterations: 1,
            dk_len: 32,
        })
        .build()
        .unwrap()
}

// ---------------------------------------------------------------------------
// Bcrypt + non-UTF-8 password — the panic.None path inside hash()
// ---------------------------------------------------------------------------

#[test]
fn bcrypt_rejects_non_utf8_password_bytes() {
    let policy = fast_test_policy(PrimaryAlgorithm::Bcrypt);
    let bad: &[u8] = &[0xff, 0xfe, 0x80, 0x81];
    let err = api::hash(&policy, bad).unwrap_err();
    assert!(matches!(err, Error::InvalidPassword(_)));
}

#[test]
fn bcrypt_verify_rejects_non_utf8_password_bytes() {
    let policy = fast_test_policy(PrimaryAlgorithm::Bcrypt);
    let stored = api::hash(&policy, "real").unwrap();
    let bad: &[u8] = &[0xff, 0xfe];
    let err = api::verify_and_upgrade(&policy, bad, &stored).unwrap_err();
    assert!(matches!(err, Error::InvalidPassword(_)));
}

// ---------------------------------------------------------------------------
// Malformed PHC / MCF strings on the verify path
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_not_a_phc_string() {
    let policy = fast_test_policy(PrimaryAlgorithm::Argon2id);
    let err = api::verify_and_upgrade(&policy, "pw", "garbage").unwrap_err();
    assert!(matches!(err, Error::InvalidHashString(_)));
}

#[test]
fn verify_rejects_unknown_algorithm_in_phc() {
    let policy = fast_test_policy(PrimaryAlgorithm::Argon2id);
    // A PHC-shaped string whose algorithm identifier passes the
    // RustCrypto password_hash parser but doesn't match any of our
    // known branches (argon2*, scrypt, pbkdf2-*). `crypt` is a real
    // PHC-spec ident that we explicitly don't handle.
    let bogus = "$crypt$YWFhYWFhYWFhYWFhYWFhYQ$dGVzdA";
    let err = api::verify_and_upgrade(&policy, "pw", bogus).unwrap_err();
    // Acceptable: either InvalidHashString (rejected at PHC parse) or
    // UnsupportedAlgorithm (rejected at our dispatch match). Both
    // are safe rejection paths — what matters is no panic / fail-open.
    assert!(matches!(
        err,
        Error::UnsupportedAlgorithm(_) | Error::InvalidHashString(_)
    ));
}

// ---------------------------------------------------------------------------
// Argon2i + Argon2d verify branches (verify-only legacy algorithms)
// ---------------------------------------------------------------------------

#[test]
fn verify_accepts_argon2i_phc_string() {
    // Hand-build an Argon2i PHC string using the engine directly.
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Version};
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(8, 1, 1, Some(32)).unwrap();
    let engine =
        Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
    let phc = engine
        .hash_password(b"pw", &salt)
        .unwrap()
        .to_string();
    assert!(phc.starts_with("$argon2i$"));

    let policy = fast_test_policy(PrimaryAlgorithm::Argon2id);
    let outcome =
        api::verify_and_upgrade(&policy, "pw", &phc).unwrap();
    assert!(outcome.is_valid());
    // Algorithm drift (i -> id) MUST trigger rehash.
    assert!(outcome.needs_rehash());
}

#[test]
fn verify_accepts_argon2d_phc_string() {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Version};
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(8, 1, 1, Some(32)).unwrap();
    let engine =
        Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
    let phc = engine
        .hash_password(b"pw", &salt)
        .unwrap()
        .to_string();
    assert!(phc.starts_with("$argon2d$"));

    let policy = fast_test_policy(PrimaryAlgorithm::Argon2id);
    let outcome =
        api::verify_and_upgrade(&policy, "pw", &phc).unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
}

#[test]
fn verify_rejects_argon2i_with_wrong_password() {
    use argon2::password_hash::{PasswordHasher, SaltString};
    use argon2::{Algorithm, Argon2, Version};
    use rand_core::OsRng;

    let salt = SaltString::generate(&mut OsRng);
    let params = argon2::Params::new(8, 1, 1, Some(32)).unwrap();
    let phc = Argon2::new(Algorithm::Argon2i, Version::V0x13, params)
        .hash_password(b"real", &salt)
        .unwrap()
        .to_string();

    let policy = fast_test_policy(PrimaryAlgorithm::Argon2id);
    let outcome =
        api::verify_and_upgrade(&policy, "wrong", &phc).unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

// ---------------------------------------------------------------------------
// PBKDF2 PHC malformed branches
// ---------------------------------------------------------------------------

#[test]
fn verify_rejects_pbkdf2_phc_missing_iteration_count() {
    let policy = fast_test_policy(PrimaryAlgorithm::Pbkdf2);
    // Drop the `i=` parameter — should fail with "missing iteration
    // count".
    let phc = "$pbkdf2-sha256$l=32$YWFhYWFhYWFhYWFhYWFhYQ$dGVzdA";
    let err = api::verify_and_upgrade(&policy, "pw", phc).unwrap_err();
    assert!(matches!(err, Error::InvalidHashString(_)));
}

#[test]
fn verify_rejects_pbkdf2_phc_bad_iteration_count() {
    let policy = fast_test_policy(PrimaryAlgorithm::Pbkdf2);
    let phc = "$pbkdf2-sha256$i=not-a-number$YWFhYWFhYWFhYWFhYWFhYQ$dGVzdA";
    let err = api::verify_and_upgrade(&policy, "pw", phc).unwrap_err();
    assert!(matches!(err, Error::InvalidHashString(_)));
}

#[test]
fn pbkdf2_sha512_phc_round_trip() {
    // Cover the Prf::Sha512 branch in api::hash + verify_pbkdf2_phc.
    let policy = PolicyBuilder::from_preset(&fast_test_policy(
        PrimaryAlgorithm::Pbkdf2,
    ))
    .pbkdf2(Pbkdf2Params {
        prf: Prf::Sha512,
        iterations: 1,
        dk_len: 64,
    })
    .build()
    .unwrap();
    let stored = api::hash(&policy, "pw").unwrap();
    assert!(stored.starts_with("$pbkdf2-sha512$"));
    let outcome = api::verify_and_upgrade(&policy, "pw", &stored).unwrap();
    assert!(outcome.is_valid());
}

#[test]
fn pbkdf2_phc_with_explicit_l_parameter() {
    // Cover the `l=` parameter parsing branch.
    let policy = fast_test_policy(PrimaryAlgorithm::Pbkdf2);
    let stored = api::hash(&policy, "pw").unwrap();
    // hash() emits both i= and l=, so a round-trip exercises both.
    assert!(stored.contains("i="));
    assert!(stored.contains("l="));
    let outcome = api::verify_and_upgrade(&policy, "pw", &stored).unwrap();
    assert!(outcome.is_valid());
}

// ---------------------------------------------------------------------------
// Pepper-prefix malformed branches (needs the pepper feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "pepper")]
mod pepper {
    use super::*;
    use hsh_kms::{KeyVersion, LocalPepper};
    use std::sync::Arc;

    fn peppered_policy() -> Policy {
        let pepper: Arc<dyn hsh_kms::Pepper> = Arc::new(
            LocalPepper::builder()
                .add(
                    KeyVersion::new(1),
                    b"pepper-key-bytes-16+++++".to_vec(),
                )
                .current(KeyVersion::new(1))
                .build()
                .unwrap(),
        );
        PolicyBuilder::from_preset(&fast_test_policy(
            PrimaryAlgorithm::Argon2id,
        ))
        .pepper_arc(pepper)
        .build()
        .unwrap()
    }

    #[test]
    fn pepper_prefix_without_colon_separator() {
        let policy = peppered_policy();
        // Strip the `:<inner>` part.
        let bogus = "hsh-pepper:nope";
        let err =
            api::verify_and_upgrade(&policy, "pw", bogus).unwrap_err();
        assert!(matches!(err, Error::InvalidHashString(_)));
    }

    #[test]
    fn pepper_prefix_with_non_integer_version() {
        let policy = peppered_policy();
        let bogus = "hsh-pepper:abc:$argon2id$dummy";
        let err =
            api::verify_and_upgrade(&policy, "pw", bogus).unwrap_err();
        assert!(matches!(err, Error::InvalidHashString(_)));
    }
}
