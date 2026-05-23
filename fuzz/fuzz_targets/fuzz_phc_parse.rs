#![no_main]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! PHC / MCF string parser must never panic on arbitrary input.

use libfuzzer_sys::fuzz_target;

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

fuzz_target!(|data: &[u8]| {
    let Ok(stored) = std::str::from_utf8(data) else {
        return;
    };
    // verify_and_upgrade with an arbitrary "stored" string. The contract
    // is that any input either returns a typed Error or an Outcome,
    // never panics.
    let _ = hsh::api::verify_and_upgrade(&weak_test_policy(), "candidate-password-123", stored);
});

