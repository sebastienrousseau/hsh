#![allow(missing_docs)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Property-based tests for the v0.0.9 enterprise surface.
//!
//! These tests exercise invariants that must hold for *any* well-formed
//! input — they don't assert a single golden answer, but a relationship
//! between inputs and outputs.

use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PrimaryAlgorithm};
use hsh::{api, Outcome};
use proptest::prelude::*;

/// A weaker policy used only by tests so the proptest runs finish in
/// reasonable wall time. **Do not use in production.**
fn fast_test_policy(primary: PrimaryAlgorithm) -> Policy {
    Policy {
        primary,
        argon2: argon2::Params::new(8, 1, 1, Some(32))
            .expect("test params"),
        bcrypt: BcryptParams::new(4),
        scrypt: ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        },
        pbkdf2: hsh::algorithms::pbkdf2::Pbkdf2Params {
            prf: hsh::algorithms::pbkdf2::Prf::Sha256,
            iterations: 1,
            dk_len: 32,
        },
        backend: hsh::Backend::Native,
        #[cfg(feature = "pepper")]
        pepper: None,
    }
}

/// Passwords are any printable ASCII between 8 and 72 bytes (the safe
/// range across all three algorithms — bcrypt rejects > 72 by default).
fn password_strategy() -> impl Strategy<Value = String> {
    "[ -~]{8,72}".prop_filter("non-empty", |s| !s.is_empty())
}

proptest! {
    #![proptest_config(ProptestConfig {
        // Keep wall-time bounded — Argon2id/bcrypt/scrypt are deliberately slow.
        // Even at fast_test_policy() params, scrypt N=2^8 is hundreds of ms.
        cases: 6,
        .. ProptestConfig::default()
    })]

    /// Hashing then verifying the **same** password must succeed.
    #[test]
    fn argon2id_round_trip_holds(pwd in password_strategy()) {
        let p = fast_test_policy(PrimaryAlgorithm::Argon2id);
        let stored = api::hash(&p, &pwd).unwrap();
        let (outcome, _) = api::verify_and_upgrade(&p, &pwd, &stored).unwrap();
        let is_valid = matches!(outcome, Outcome::Valid { .. });
        prop_assert!(is_valid);
    }

    /// Hashing then verifying a **different** password must fail.
    #[test]
    fn argon2id_rejects_distinct_passwords(
        a in password_strategy(),
        b in password_strategy(),
    ) {
        prop_assume!(a != b);
        let p = fast_test_policy(PrimaryAlgorithm::Argon2id);
        let stored = api::hash(&p, &a).unwrap();
        let (outcome, _) = api::verify_and_upgrade(&p, &b, &stored).unwrap();
        let is_invalid = matches!(outcome, Outcome::Invalid);
        prop_assert!(is_invalid);
    }

    /// Bcrypt round-trip must hold within the 72-byte safety rail.
    #[test]
    fn bcrypt_round_trip_holds(pwd in password_strategy()) {
        let p = fast_test_policy(PrimaryAlgorithm::Bcrypt);
        let stored = api::hash(&p, &pwd).unwrap();
        let (outcome, _) = api::verify_and_upgrade(&p, &pwd, &stored).unwrap();
        let is_valid = matches!(outcome, Outcome::Valid { .. });
        prop_assert!(is_valid);
    }

    /// Scrypt round-trip must hold.
    #[test]
    fn scrypt_round_trip_holds(pwd in password_strategy()) {
        let p = fast_test_policy(PrimaryAlgorithm::Scrypt);
        let stored = api::hash(&p, &pwd).unwrap();
        let (outcome, _) = api::verify_and_upgrade(&p, &pwd, &stored).unwrap();
        let is_valid = matches!(outcome, Outcome::Valid { .. });
        prop_assert!(is_valid);
    }

    /// Two distinct hashes of the same password must differ (salt
    /// uniqueness) — proves OsRng-based salt is not reused.
    #[test]
    fn salts_make_each_hash_distinct(pwd in password_strategy()) {
        let p = fast_test_policy(PrimaryAlgorithm::Argon2id);
        let a = api::hash(&p, &pwd).unwrap();
        let b = api::hash(&p, &pwd).unwrap();
        prop_assert_ne!(a, b);
    }

    /// Bcrypt must reject inputs strictly longer than 72 bytes (#158).
    #[test]
    fn bcrypt_rejects_oversize_input(extra in 1usize..32usize) {
        let pwd = "x".repeat(72 + extra);
        let p = fast_test_policy(PrimaryAlgorithm::Bcrypt);
        let err = api::hash(&p, &pwd).unwrap_err();
        let is_invalid_password = matches!(err, hsh::Error::InvalidPassword(_));
        prop_assert!(is_invalid_password);
    }

    /// The legacy `Hash::new(pwd, salt, algo)` must require >= 8 chars.
    #[test]
    fn short_passwords_are_rejected(len in 0usize..8usize) {
        let pwd = "x".repeat(len);
        let r = hsh::models::hash::Hash::new(&pwd, "abcdefghijklmnop", "argon2id");
        prop_assert!(r.is_err());
    }
}
