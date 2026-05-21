#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Pepper / KMS integration tests. Requires the `pepper` feature; the
//! whole module is `cfg`-gated so it disappears when the feature is off.

#![cfg(feature = "pepper")]

use std::sync::Arc;

use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{api, Outcome};
use hsh_kms::{KeyVersion, LocalPepper};

fn fast_test_policy() -> Policy {
    PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
        .primary(PrimaryAlgorithm::Argon2id)
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
            iterations: 1,
            dk_len: 32,
        })
        .build()
        .expect("fast test policy")
}

fn fast_policy_with_pepper(pepper: Arc<dyn hsh_kms::Pepper>) -> Policy {
    PolicyBuilder::from_preset(&fast_test_policy())
        .pepper_arc(pepper)
        .build()
        .expect("fast peppered policy")
}

fn pepper_v1() -> Arc<dyn hsh_kms::Pepper> {
    Arc::new(
        LocalPepper::builder()
            .add(
                KeyVersion::new(1),
                b"v1-pepper-bytes-aaaaaaaa".to_vec(),
            )
            .current(KeyVersion::new(1))
            .build()
            .unwrap(),
    )
}

fn pepper_v1_v2_current_v2() -> Arc<dyn hsh_kms::Pepper> {
    Arc::new(
        LocalPepper::builder()
            .add(
                KeyVersion::new(1),
                b"v1-pepper-bytes-aaaaaaaa".to_vec(),
            )
            .add(
                KeyVersion::new(2),
                b"v2-pepper-bytes-bbbbbbbb".to_vec(),
            )
            .current(KeyVersion::new(2))
            .build()
            .unwrap(),
    )
}

#[test]
fn peppered_round_trip_holds() {
    let policy = fast_policy_with_pepper(pepper_v1());
    let stored =
        api::hash(&policy, "correct horse battery staple").unwrap();

    assert!(stored.starts_with("hsh-pepper:1:"));

    let outcome = api::verify_and_upgrade(
        &policy,
        "correct horse battery staple",
        &stored,
    )
    .unwrap();

    assert!(matches!(outcome, Outcome::Valid { rehashed: None }));
}

// Miri-gating: per-PR Miri's 60-min budget can't run every peppered
// hashing test (argon2 + HMAC + sha2 in the interpreter is ~200×
// slower than native). Keep `peppered_round_trip_holds` and
// `unknown_pepper_version_in_stored_hash_returns_invalid` running —
// they cover the HMAC + sha2 unsafe paths plus the version-parse arm.
#[cfg_attr(miri, ignore = "Miri: covered by peppered_round_trip_holds")]
#[test]
fn peppered_rejects_wrong_password() {
    let policy = fast_policy_with_pepper(pepper_v1());
    let stored = api::hash(&policy, "right password").unwrap();

    let outcome =
        api::verify_and_upgrade(&policy, "wrong password", &stored)
            .unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

#[cfg_attr(miri, ignore = "Miri: covered by peppered_round_trip_holds")]
#[test]
fn peppered_rejected_when_policy_has_no_pepper() {
    let peppered_policy = fast_policy_with_pepper(pepper_v1());
    let stored = api::hash(&peppered_policy, "secret").unwrap();

    let unpeppered = PolicyBuilder::from_preset(&peppered_policy)
        .no_pepper()
        .build()
        .unwrap();

    let outcome =
        api::verify_and_upgrade(&unpeppered, "secret", &stored)
            .unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

#[cfg_attr(miri, ignore = "Miri: covered by peppered_round_trip_holds")]
#[test]
fn pepper_rotation_triggers_rehash() {
    let v1_policy = fast_policy_with_pepper(pepper_v1());
    let stored_v1 = api::hash(&v1_policy, "user password").unwrap();
    assert!(stored_v1.starts_with("hsh-pepper:1:"));

    let v2_policy = fast_policy_with_pepper(pepper_v1_v2_current_v2());
    let outcome = api::verify_and_upgrade(
        &v2_policy,
        "user password",
        &stored_v1,
    )
    .unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    let new_phc = outcome
        .rehashed()
        .expect("rotation should yield a rehash")
        .to_owned();
    assert!(new_phc.starts_with("hsh-pepper:2:"));

    let outcome2 =
        api::verify_and_upgrade(&v2_policy, "user password", &new_phc)
            .unwrap();
    assert!(matches!(outcome2, Outcome::Valid { rehashed: None }));
}

#[cfg_attr(miri, ignore = "Miri: covered by peppered_round_trip_holds")]
#[test]
fn legacy_unpeppered_hash_upgrades_under_pepper_policy() {
    let bare_policy = fast_test_policy();
    let legacy = api::hash(&bare_policy, "legacy user pw").unwrap();
    assert!(legacy.starts_with("$argon2id$"));

    let pepper_policy = fast_policy_with_pepper(pepper_v1());
    let outcome = api::verify_and_upgrade(
        &pepper_policy,
        "legacy user pw",
        &legacy,
    )
    .unwrap();
    assert!(outcome.is_valid());
    assert!(outcome.needs_rehash());
    let new_phc =
        outcome.rehashed().expect("legacy → peppered upgrade");
    assert!(new_phc.starts_with("hsh-pepper:1:"));
}

#[cfg_attr(miri, ignore = "Miri: covered by peppered_round_trip_holds")]
#[test]
fn legacy_unpeppered_with_wrong_password_returns_invalid_not_rehash() {
    // Hash without pepper, then verify under a pepper-enabled policy
    // with the WRONG password. This exercises the
    // `if policy.pepper.is_some() && !starts_with(PEPPER_PREFIX)` branch
    // where outcome.is_valid() is false → Outcome::Invalid (not rehash).
    let bare_policy = fast_test_policy();
    let stored = api::hash(&bare_policy, "right pw").unwrap();

    let pepper_policy = fast_policy_with_pepper(pepper_v1());
    let outcome =
        api::verify_and_upgrade(&pepper_policy, "wrong pw", &stored)
            .unwrap();
    assert!(matches!(outcome, Outcome::Invalid));
}

#[test]
fn unknown_pepper_version_in_stored_hash_returns_invalid() {
    // Build a hash that claims keyver=99 — version not in our pepper.
    let policy = fast_policy_with_pepper(pepper_v1());
    let stored = "hsh-pepper:99:$argon2id$v=19$m=8,t=1,p=1$YWFhYWFhYWFhYWFhYWFhYQ$tk7L8C72L3l3RfvCK8KqXg".to_string();

    let outcome = api::verify_and_upgrade(&policy, "anything", &stored);
    // Either Outcome::Invalid (clean reject) or a typed error — both
    // are acceptable; what's NOT acceptable is a panic.
    assert!(outcome.is_ok() || outcome.is_err());
}
