#![allow(missing_docs)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PBKDF2 + Backend integration tests.

use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PrimaryAlgorithm};
use hsh::{api, Backend, Outcome};

fn fast_pbkdf2_policy() -> Policy {
    Policy {
        primary: PrimaryAlgorithm::Pbkdf2,
        backend: Backend::Native,
        argon2: argon2::Params::new(8, 1, 1, Some(32)).unwrap(),
        bcrypt: BcryptParams::new(4),
        scrypt: ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        },
        pbkdf2: Pbkdf2Params {
            prf: Prf::Sha256,
            iterations: 1_000, // fast for tests; OWASP-2025 = 600_000
            dk_len: 32,
        },
        #[cfg(feature = "pepper")]
        pepper: None,
    }
}

#[test]
fn pbkdf2_round_trip_holds() {
    let policy = fast_pbkdf2_policy();
    let stored =
        api::hash(&policy, "correct horse battery staple").unwrap();
    assert!(stored.starts_with("$pbkdf2-sha256$"));

    let (outcome, rehashed) = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )
    .unwrap();

    assert!(matches!(
        outcome,
        Outcome::Valid {
            needs_rehash: false
        }
    ));
    assert!(rehashed.is_none());
}

#[test]
fn pbkdf2_rejects_wrong_password() {
    let policy = fast_pbkdf2_policy();
    let stored = api::hash(&policy, "correct").unwrap();

    let (outcome, _) =
        api::verify_and_upgrade(&policy, "wrong", &stored).unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

#[test]
fn pbkdf2_iteration_drift_triggers_rehash() {
    let weak = fast_pbkdf2_policy(); // 1_000 iters
    let stored = api::hash(&weak, "user pw").unwrap();

    let mut strong = fast_pbkdf2_policy();
    strong.pbkdf2.iterations = 10_000;

    let (outcome, rehashed) =
        api::verify_and_upgrade(&strong, "user pw", &stored).unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    let new_phc = rehashed.expect("iteration drift should rehash");
    assert!(new_phc.starts_with("$pbkdf2-sha256$i=10000,"));
}

#[test]
fn pbkdf2_prf_drift_triggers_rehash() {
    // Hash with SHA-256, then verify under SHA-512 policy.
    let sha256_policy = fast_pbkdf2_policy();
    let stored = api::hash(&sha256_policy, "user pw").unwrap();

    let mut sha512_policy = fast_pbkdf2_policy();
    sha512_policy.pbkdf2.prf = Prf::Sha512;

    let (outcome, rehashed) =
        api::verify_and_upgrade(&sha512_policy, "user pw", &stored)
            .unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    assert!(rehashed
        .expect("PRF drift should rehash")
        .starts_with("$pbkdf2-sha512$"));
}

#[test]
fn fips_policy_refuses_to_mint_argon2id() {
    // Construct a FIPS policy but with Argon2id as primary — that's
    // an internal contradiction the API must refuse.
    let mut bad_policy = Policy::fips_140_pbkdf2();
    bad_policy.primary = PrimaryAlgorithm::Argon2id;

    let err = api::hash(&bad_policy, "user pw").unwrap_err();
    assert!(
        matches!(err, hsh::Error::InvalidParameter(ref s) if s.contains("FIPS"))
    );
}

#[test]
fn fips_policy_refuses_when_feature_not_enabled() {
    // `fips_available_in_build()` is hardcoded false today. Even a
    // correctly-shaped FIPS policy is refused to avoid fail-open.
    let policy = Policy::fips_140_pbkdf2();
    let err = api::hash(&policy, "user pw").unwrap_err();
    assert!(
        matches!(err, hsh::Error::InvalidParameter(ref s) if s.contains("fips"))
    );
}

#[test]
fn backend_is_fips_round_trips() {
    assert!(Backend::Fips140Required.is_fips());
    assert!(!Backend::Native.is_fips());
    assert!(!Backend::fips_available_in_build());
}

#[test]
fn policy_fips_140_pbkdf2_uses_pbkdf2_primary() {
    let policy = Policy::fips_140_pbkdf2();
    assert!(matches!(policy.primary, PrimaryAlgorithm::Pbkdf2));
    assert!(policy.backend.is_fips());
    assert_eq!(policy.pbkdf2.iterations, 600_000);
}
