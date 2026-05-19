#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Argon2id verify path: arbitrary password against a fixed valid
//! reference hash must never panic and must return `Outcome::Invalid`
//! when the candidate is not the reference plaintext.

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const REFERENCE_PASSWORD: &str = "fuzz-reference-pw-do-not-match";

fn weak_test_policy() -> hsh::Policy {
    hsh::policy::PolicyBuilder::from_preset(&hsh::Policy::owasp_minimum_2025())
        .primary(hsh::PrimaryAlgorithm::Argon2id)
        .argon2(argon2::Params::new(8, 1, 1, Some(32)).expect("test params"))
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
        .expect("weak test policy")
}

fn reference_hash() -> &'static str {
    static REF: OnceLock<String> = OnceLock::new();
    REF.get_or_init(|| {
        hsh::api::hash(&weak_test_policy(), REFERENCE_PASSWORD)
            .expect("reference hash must succeed")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(candidate) = std::str::from_utf8(data) else {
        return;
    };
    let stored = reference_hash();
    let Ok((outcome, _)) = hsh::api::verify_and_upgrade(&weak_test_policy(), candidate, stored) else {
        return;
    };
    // The only way an arbitrary candidate equals the reference is if it
    // happens to be REFERENCE_PASSWORD itself.
    if candidate != REFERENCE_PASSWORD {
        assert!(!outcome.is_valid(), "unexpected match for {candidate:?}");
    }
});

