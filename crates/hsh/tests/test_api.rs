#![allow(missing_docs)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::api;
    use hsh::policy::{Policy, PrimaryAlgorithm};
    use hsh::Outcome;

    /// A weaker policy used only by tests so the suite finishes in
    /// reasonable wall time. **Do not use in production.**
    fn fast_test_policy() -> Policy {
        Policy {
            primary: PrimaryAlgorithm::Argon2id,
            argon2: argon2::Params::new(8, 1, 1, Some(32))
                .expect("test params"),
            bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
            scrypt: hsh::algorithms::scrypt::ScryptParams {
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

    #[test]
    fn argon2id_round_trip() {
        let policy = fast_test_policy();
        let stored =
            api::hash(&policy, "correct horse battery staple").unwrap();

        // PHC strings start with $argon2id$
        assert!(stored.starts_with("$argon2id$"));

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
    fn argon2id_rejects_wrong_password() {
        let policy = fast_test_policy();
        let stored = api::hash(&policy, "correct horse").unwrap();

        let (outcome, rehashed) =
            api::verify_and_upgrade(&policy, "wrong horse", &stored)
                .unwrap();

        assert!(matches!(outcome, Outcome::Invalid));
        assert!(rehashed.is_none());
    }

    #[test]
    fn argon2id_triggers_rehash_when_policy_strengthens() {
        // Hash under weak params, then verify under a stronger policy and
        // confirm the verifier asks for a rehash.
        let weak = Policy {
            primary: PrimaryAlgorithm::Argon2id,
            argon2: argon2::Params::new(8, 1, 1, Some(32))
                .expect("weak"),
            bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
            scrypt: hsh::algorithms::scrypt::ScryptParams {
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
        };
        let strong = Policy {
            primary: PrimaryAlgorithm::Argon2id,
            argon2: argon2::Params::new(16, 2, 1, Some(32))
                .expect("strong"),
            bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
            scrypt: hsh::algorithms::scrypt::ScryptParams {
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
        };

        let stored = api::hash(&weak, "secret password").unwrap();
        let (outcome, rehashed) = api::verify_and_upgrade(
            &strong,
            "secret password",
            &stored,
        )
        .unwrap();

        assert!(outcome.is_valid());
        assert!(outcome.needs_rehash());
        let new_phc =
            rehashed.expect("policy drift should yield rehash");
        assert!(new_phc.starts_with("$argon2id$"));

        // The rehashed PHC must verify cleanly under the strong policy
        // and *not* need another rehash.
        let (outcome2, rehashed2) = api::verify_and_upgrade(
            &strong,
            "secret password",
            &new_phc,
        )
        .unwrap();
        assert!(matches!(
            outcome2,
            Outcome::Valid {
                needs_rehash: false
            }
        ));
        assert!(rehashed2.is_none());
    }

    #[test]
    fn bcrypt_mcf_round_trip() {
        let policy = Policy {
            primary: PrimaryAlgorithm::Bcrypt,
            argon2: argon2::Params::new(8, 1, 1, Some(32))
                .expect("test params"),
            bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
            scrypt: hsh::algorithms::scrypt::ScryptParams {
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
        };
        let stored = api::hash(&policy, "secret password").unwrap();
        assert!(stored.starts_with("$2"));

        let (outcome, rehashed) = api::verify_and_upgrade(
            &policy,
            "secret password",
            &stored,
        )
        .unwrap();
        assert!(outcome.is_valid());
        assert!(rehashed.is_none());
    }

    #[test]
    fn bcrypt_then_upgrade_to_argon2id() {
        // Store under bcrypt, then verify under an Argon2id-primary policy.
        let bcrypt_policy = Policy {
            primary: PrimaryAlgorithm::Bcrypt,
            argon2: argon2::Params::new(8, 1, 1, Some(32))
                .expect("test params"),
            bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
            scrypt: hsh::algorithms::scrypt::ScryptParams {
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
        };
        let argon_policy = fast_test_policy();

        let stored =
            api::hash(&bcrypt_policy, "legacy password").unwrap();
        let (outcome, rehashed) = api::verify_and_upgrade(
            &argon_policy,
            "legacy password",
            &stored,
        )
        .unwrap();

        assert!(outcome.is_valid());
        assert!(outcome.needs_rehash());
        let new_phc =
            rehashed.expect("algorithm drift should yield rehash");
        assert!(new_phc.starts_with("$argon2id$"));
    }
}
