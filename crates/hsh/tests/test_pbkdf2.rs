#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! PBKDF2 + Backend integration tests.

use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{api, Backend, Outcome};

fn fast_pbkdf2_policy() -> Policy {
    PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
        .primary(PrimaryAlgorithm::Pbkdf2)
        .argon2(argon2::Params::new(8, 1, 1, Some(32)).unwrap())
        .bcrypt(BcryptParams::new(4))
        .scrypt(ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        })
        .pbkdf2(Pbkdf2Params {
            prf: Prf::Sha256,
            iterations: 1_000,
            dk_len: 32,
        })
        .build()
        .expect("fast PBKDF2 policy")
}

#[test]
fn pbkdf2_round_trip_holds() {
    let policy = fast_pbkdf2_policy();
    let stored =
        api::hash(&policy, "correct horse battery staple").unwrap();
    assert!(stored.starts_with("$pbkdf2-sha256$"));

    let outcome = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )
    .unwrap();

    assert!(matches!(outcome, Outcome::Valid { rehashed: None }));
}

#[test]
fn pbkdf2_rejects_wrong_password() {
    let policy = fast_pbkdf2_policy();
    let stored = api::hash(&policy, "correct").unwrap();

    let outcome =
        api::verify_and_upgrade(&policy, "wrong", &stored).unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

#[test]
fn pbkdf2_iteration_drift_triggers_rehash() {
    let weak = fast_pbkdf2_policy(); // 1_000 iters
    let stored = api::hash(&weak, "user pw").unwrap();

    let strong = PolicyBuilder::from_preset(&fast_pbkdf2_policy())
        .pbkdf2(Pbkdf2Params {
            prf: Prf::Sha256,
            iterations: 10_000,
            dk_len: 32,
        })
        .build()
        .unwrap();

    let outcome =
        api::verify_and_upgrade(&strong, "user pw", &stored).unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    let new_phc =
        outcome.rehashed().expect("iteration drift should rehash");
    assert!(new_phc.starts_with("$pbkdf2-sha256$i=10000,"));
}

#[test]
fn pbkdf2_prf_drift_triggers_rehash() {
    let sha256_policy = fast_pbkdf2_policy();
    let stored = api::hash(&sha256_policy, "user pw").unwrap();

    let sha512_policy =
        PolicyBuilder::from_preset(&fast_pbkdf2_policy())
            .pbkdf2(Pbkdf2Params {
                prf: Prf::Sha512,
                iterations: 1_000,
                dk_len: 32,
            })
            .build()
            .unwrap();

    let outcome =
        api::verify_and_upgrade(&sha512_policy, "user pw", &stored)
            .unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    assert!(outcome
        .rehashed()
        .expect("PRF drift should rehash")
        .starts_with("$pbkdf2-sha512$"));
}

#[test]
fn fips_policy_refuses_to_mint_argon2id() {
    let bad_policy =
        PolicyBuilder::from_preset(&Policy::fips_140_pbkdf2())
            .primary(PrimaryAlgorithm::Argon2id)
            .build()
            .unwrap();

    let err = api::hash(&bad_policy, "user pw").unwrap_err();
    assert!(
        matches!(err, hsh::Error::InvalidParameter(ref s) if s.contains("FIPS"))
    );
}

#[cfg(not(feature = "fips"))]
#[test]
fn fips_policy_refuses_when_feature_not_enabled() {
    let policy = Policy::fips_140_pbkdf2();
    let err = api::hash(&policy, "user pw").unwrap_err();
    assert!(
        matches!(err, hsh::Error::InvalidParameter(ref s) if s.contains("fips"))
    );
}

#[cfg(feature = "fips")]
#[test]
fn fips_policy_mints_when_feature_enabled() {
    // With the `fips` feature on, hsh-backend-awslc is in the dep
    // graph and Backend::fips_available_in_build() returns true, so
    // api::hash mints a real PBKDF2-HMAC-SHA-256 hash via AWS-LC.
    let policy = Policy::fips_140_pbkdf2();
    let hash =
        api::hash(&policy, "user pw").expect("FIPS hash must succeed");
    assert!(hash.starts_with("$pbkdf2-sha256$"));
}

#[test]
fn backend_is_fips_round_trips() {
    assert!(Backend::Fips140Required.is_fips());
    assert!(!Backend::Native.is_fips());
    // fips_available_in_build is now feature-gated: false in the
    // default build, true when the `fips` feature pulls in
    // hsh-backend-awslc → aws-lc-rs.
    assert_eq!(
        Backend::fips_available_in_build(),
        cfg!(feature = "fips"),
        "fips_available_in_build must mirror the `fips` Cargo feature"
    );
}

#[test]
fn policy_fips_140_pbkdf2_uses_pbkdf2_primary() {
    let policy = Policy::fips_140_pbkdf2();
    assert!(matches!(policy.primary(), PrimaryAlgorithm::Pbkdf2));
    assert!(policy.backend().is_fips());
    assert_eq!(policy.pbkdf2_params().iterations, 600_000);
}

#[test]
fn policy_builder_requires_primary_when_blank() {
    let err = PolicyBuilder::new().build().unwrap_err();
    assert!(matches!(err, hsh::Error::InvalidPolicy(_)));
}
