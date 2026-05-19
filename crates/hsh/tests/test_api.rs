#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::api;
    use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
    use hsh::Outcome;

    /// A weaker policy used only by tests so the suite finishes in
    /// reasonable wall time. **Do not use in production.**
    fn fast_test_policy() -> Policy {
        fast_policy_with_primary(PrimaryAlgorithm::Argon2id)
    }

    fn fast_policy_with_primary(primary: PrimaryAlgorithm) -> Policy {
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
            .pbkdf2(hsh::algorithms::pbkdf2::Pbkdf2Params {
                prf: hsh::algorithms::pbkdf2::Prf::Sha256,
                iterations: 1,
                dk_len: 32,
            })
            .build()
            .expect("fast test policy")
    }

    #[test]
    fn argon2id_round_trip() {
        let policy = fast_test_policy();
        let stored =
            api::hash(&policy, "correct horse battery staple").unwrap();

        assert!(stored.starts_with("$argon2id$"));

        let outcome = api::verify_and_upgrade(
            &policy,
            "correct horse battery staple",
            &stored,
        )
        .unwrap();

        assert!(matches!(outcome, Outcome::Valid { rehashed: None }));
    }

    #[test]
    fn argon2id_rejects_wrong_password() {
        let policy = fast_test_policy();
        let stored = api::hash(&policy, "correct horse").unwrap();

        let outcome =
            api::verify_and_upgrade(&policy, "wrong horse", &stored)
                .unwrap();

        assert!(matches!(outcome, Outcome::Invalid));
    }

    #[test]
    fn argon2id_triggers_rehash_when_policy_strengthens() {
        let weak = fast_test_policy();
        let strong = PolicyBuilder::from_preset(&fast_test_policy())
            .argon2(argon2::Params::new(16, 2, 1, Some(32)).unwrap())
            .build()
            .unwrap();

        let stored = api::hash(&weak, "secret password").unwrap();
        let outcome = api::verify_and_upgrade(
            &strong,
            "secret password",
            &stored,
        )
        .unwrap();

        assert!(outcome.is_valid());
        assert!(outcome.needs_rehash());
        let new_phc = outcome
            .rehashed()
            .expect("policy drift should yield rehash")
            .to_owned();
        assert!(new_phc.starts_with("$argon2id$"));

        let outcome2 = api::verify_and_upgrade(
            &strong,
            "secret password",
            &new_phc,
        )
        .unwrap();
        assert!(matches!(outcome2, Outcome::Valid { rehashed: None }));
    }

    #[test]
    fn bcrypt_mcf_round_trip() {
        let policy = fast_policy_with_primary(PrimaryAlgorithm::Bcrypt);
        let stored = api::hash(&policy, "secret password").unwrap();
        assert!(stored.starts_with("$2"));

        let outcome = api::verify_and_upgrade(
            &policy,
            "secret password",
            &stored,
        )
        .unwrap();
        assert!(outcome.is_valid());
        assert!(!outcome.needs_rehash());
    }

    #[test]
    fn bcrypt_then_upgrade_to_argon2id() {
        let bcrypt_policy =
            fast_policy_with_primary(PrimaryAlgorithm::Bcrypt);
        let argon_policy = fast_test_policy();

        let stored =
            api::hash(&bcrypt_policy, "legacy password").unwrap();
        let outcome = api::verify_and_upgrade(
            &argon_policy,
            "legacy password",
            &stored,
        )
        .unwrap();

        assert!(outcome.is_valid());
        assert!(outcome.needs_rehash());
        let new_phc = outcome
            .rehashed()
            .expect("algorithm drift should yield rehash");
        assert!(new_phc.starts_with("$argon2id$"));
    }
}
