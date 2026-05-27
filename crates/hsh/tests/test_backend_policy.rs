#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage tests for `Backend`, `Policy`, `PolicyBuilder`, `Outcome`
//! accessors. Most of the algorithmic paths are covered by
//! `test_api.rs` / `test_pbkdf2.rs` / `test_pepper.rs`; this file
//! pins down the metadata + builder + accessor surface.

use hsh::algorithms::bcrypt::{BcryptParams, PrehashAlgorithm};
use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::algorithms::scrypt::ScryptParams;
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{Backend, Outcome};

// ---------------------------------------------------------------- Backend
#[test]
fn backend_default_is_native() {
    assert_eq!(Backend::default(), Backend::Native);
    assert!(!Backend::Native.is_fips());
    assert!(Backend::Fips140Required.is_fips());
}

#[test]
fn fips_available_mirrors_cargo_feature() {
    // True when the `fips` feature pulls hsh-backend-awslc into the
    // dep graph (which in turn routes PBKDF2 through aws-lc-rs FIPS
    // 3.0); false otherwise.
    assert_eq!(
        Backend::fips_available_in_build(),
        cfg!(feature = "fips")
    );
}

// ---------------------------------------------------------------- Outcome
#[test]
fn outcome_is_valid_and_needs_rehash() {
    let valid_no_rehash = Outcome::Valid { rehashed: None };
    let valid_rehash = Outcome::Valid {
        rehashed: Some(String::from("placeholder")),
    };
    let invalid = Outcome::Invalid;

    assert!(valid_no_rehash.is_valid());
    assert!(!valid_no_rehash.needs_rehash());
    assert!(valid_rehash.is_valid());
    assert!(valid_rehash.needs_rehash());
    assert!(!invalid.is_valid());
    assert!(!invalid.needs_rehash());
}

// ---------------------------------------------------------------- Policy presets
#[test]
fn owasp_minimum_2025_uses_argon2id() {
    let p = Policy::owasp_minimum_2025();
    assert_eq!(p.primary(), PrimaryAlgorithm::Argon2id);
    assert_eq!(p.backend(), Backend::Native);
    assert_eq!(p.argon2_params().m_cost(), 19_456);
}

#[test]
fn rfc9106_first_recommended_uses_high_memory() {
    let p = Policy::rfc9106_first_recommended();
    assert_eq!(p.primary(), PrimaryAlgorithm::Argon2id);
    assert_eq!(p.argon2_params().m_cost(), 1 << 21);
}

#[test]
fn fips_140_pbkdf2_carries_fips_marker() {
    let p = Policy::fips_140_pbkdf2();
    assert_eq!(p.primary(), PrimaryAlgorithm::Pbkdf2);
    assert!(p.backend().is_fips());
    assert_eq!(p.pbkdf2_params().iterations, 600_000);
}

#[test]
fn policy_default_is_owasp() {
    let p = Policy::default();
    assert_eq!(p.primary(), PrimaryAlgorithm::Argon2id);
}

// ---------------------------------------------------------------- Accessors
#[test]
fn policy_accessors_return_configured_values() {
    let scrypt_params = ScryptParams {
        log_n: 12,
        r: 8,
        p: 1,
        dk_len: 32,
    };
    let bcrypt_params = BcryptParams::new(7);
    let pbkdf2_params = Pbkdf2Params {
        prf: Prf::Sha512,
        iterations: 200_000,
        dk_len: 64,
    };
    let argon2_params =
        argon2::Params::new(12, 3, 1, Some(32)).unwrap();

    let p = PolicyBuilder::new()
        .primary(PrimaryAlgorithm::Argon2id)
        .backend(Backend::Native)
        .argon2(argon2_params.clone())
        .bcrypt(bcrypt_params)
        .scrypt(scrypt_params)
        .pbkdf2(pbkdf2_params)
        .build()
        .unwrap();

    assert_eq!(p.primary(), PrimaryAlgorithm::Argon2id);
    assert_eq!(p.backend(), Backend::Native);
    assert_eq!(p.argon2_params().m_cost(), argon2_params.m_cost());
    assert_eq!(p.bcrypt_params().cost, 7);
    assert_eq!(p.scrypt_params().log_n, 12);
    assert_eq!(p.pbkdf2_params().iterations, 200_000);
    assert!(!p.has_pepper());
}

#[test]
fn policy_to_builder_round_trips() {
    let original = Policy::owasp_minimum_2025();
    let cloned = original.to_builder().build().unwrap();
    assert_eq!(original.primary(), cloned.primary());
    assert_eq!(original.backend(), cloned.backend());
    assert_eq!(
        original.pbkdf2_params().iterations,
        cloned.pbkdf2_params().iterations,
    );
}

// ---------------------------------------------------------------- Builder
#[test]
fn builder_new_default_is_blank() {
    // Default builder errors because primary isn't set.
    let err = PolicyBuilder::default().build().unwrap_err();
    assert!(matches!(err, hsh::Error::InvalidPolicy(_)));
}

#[test]
fn builder_chain_overrides_in_order() {
    let p = PolicyBuilder::new()
        .primary(PrimaryAlgorithm::Argon2id)
        .primary(PrimaryAlgorithm::Bcrypt) // override
        .build()
        .unwrap();
    assert_eq!(p.primary(), PrimaryAlgorithm::Bcrypt);
}

#[test]
fn builder_inherits_defaults_for_unset_fields() {
    let p = PolicyBuilder::new()
        .primary(PrimaryAlgorithm::Argon2id)
        .build()
        .unwrap();
    // Backend defaults to Native; argon2 to OWASP minimum.
    assert_eq!(p.backend(), Backend::Native);
    assert_eq!(p.argon2_params().m_cost(), 19_456);
}

// ---------------------------------------------------------------- Pepper-feature gated
#[cfg(feature = "pepper")]
mod pepper_tests {
    use super::*;
    use hsh_kms::{KeyVersion, LocalPepper};
    use std::sync::Arc;

    fn test_pepper() -> LocalPepper {
        LocalPepper::builder()
            .add(
                KeyVersion::new(1),
                b"v1-test-pepper-key-16+ bytes".to_vec(),
            )
            .current(KeyVersion::new(1))
            .build()
            .unwrap()
    }

    #[test]
    fn policy_with_pepper_sets_flag() {
        let p = Policy::owasp_minimum_2025().with_pepper(test_pepper());
        assert!(p.has_pepper());
    }

    #[test]
    fn policy_with_pepper_arc_sets_flag() {
        let arc: Arc<dyn hsh_kms::Pepper> = Arc::new(test_pepper());
        let p = Policy::owasp_minimum_2025().with_pepper_arc(arc);
        assert!(p.has_pepper());
    }

    #[test]
    fn builder_pepper_setter_and_no_pepper() {
        let with = PolicyBuilder::new()
            .primary(PrimaryAlgorithm::Argon2id)
            .pepper(test_pepper())
            .build()
            .unwrap();
        assert!(with.has_pepper());

        let without = PolicyBuilder::from_preset(&with)
            .no_pepper()
            .build()
            .unwrap();
        assert!(!without.has_pepper());
    }
}

// ---------------------------------------------------------------- Bcrypt safety rail
#[test]
fn bcrypt_safety_rail_rejects_long_input() {
    let policy =
        PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
            .primary(PrimaryAlgorithm::Bcrypt)
            .bcrypt(BcryptParams::new(4))
            .build()
            .unwrap();
    let too_long = "x".repeat(100);
    let err = hsh::api::hash(&policy, &too_long).unwrap_err();
    assert!(matches!(err, hsh::Error::InvalidPassword(_)));
}

#[test]
fn bcrypt_with_prehash_accepts_long_input() {
    let policy =
        PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
            .primary(PrimaryAlgorithm::Bcrypt)
            .bcrypt(
                BcryptParams::new(4)
                    .with_prehash(PrehashAlgorithm::Sha256),
            )
            .build()
            .unwrap();
    let too_long = "x".repeat(100);
    // With pre-hash, long input is accepted. Stored format carries the
    // hsh-bcrypt-sha256: envelope so verify_and_upgrade can route to the
    // matching prehash mode at verify time.
    let stored = hsh::api::hash(&policy, &too_long).unwrap();
    assert!(stored.starts_with("hsh-bcrypt-sha256:"));
    let inner = stored
        .strip_prefix("hsh-bcrypt-sha256:")
        .expect("envelope present");
    assert!(inner.starts_with("$2"));
    // Round-trip through verify to prove the envelope's verify path works.
    let outcome =
        hsh::api::verify_and_upgrade(&policy, &too_long, &stored)
            .unwrap();
    assert!(matches!(outcome, Outcome::Valid { rehashed: None }));
}

#[test]
fn bcrypt_params_default_and_new() {
    let default = BcryptParams::default();
    assert!(matches!(default.prehash, PrehashAlgorithm::None));
    let custom = BcryptParams::new(11);
    assert_eq!(custom.cost, 11);
    assert!(matches!(custom.prehash, PrehashAlgorithm::None));
}

// ---------------------------------------------------------------- Scrypt params
#[test]
fn scrypt_params_default_is_owasp_minimum() {
    let p = ScryptParams::default();
    assert_eq!(p.log_n, 17);
    assert_eq!(p.r, 8);
    assert_eq!(p.p, 1);
}

// ---------------------------------------------------------------- PBKDF2 params
#[test]
fn pbkdf2_owasp_2025_preset_uses_sha256() {
    let p = Pbkdf2Params::owasp_minimum_2025();
    assert!(matches!(p.prf, Prf::Sha256));
    assert_eq!(p.iterations, 600_000);
    assert_eq!(p.dk_len, 32);
}

#[test]
fn pbkdf2_owasp_2025_sha512_preset() {
    let p = Pbkdf2Params::owasp_minimum_2025_sha512();
    assert!(matches!(p.prf, Prf::Sha512));
    assert_eq!(p.iterations, 210_000);
}

#[test]
fn prf_phc_ids() {
    assert_eq!(Prf::Sha256.phc_id(), "pbkdf2-sha256");
    assert_eq!(Prf::Sha512.phc_id(), "pbkdf2-sha512");
}

#[test]
fn prf_default_is_sha256() {
    assert!(matches!(Prf::default(), Prf::Sha256));
}
