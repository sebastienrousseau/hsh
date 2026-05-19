#![no_main]
//! Bcrypt verify path: arbitrary candidate against a fixed reference
//! MCF string. Tests the bcrypt safety-rail and 72-byte truncation
//! handling don't panic.

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const REFERENCE_PASSWORD: &str = "fuzz-reference-bcrypt";

fn bcrypt_test_policy() -> hsh::Policy {
    hsh::Policy {
        primary: hsh::PrimaryAlgorithm::Bcrypt,
        argon2: argon2::Params::new(8, 1, 1, Some(32))
            .expect("test params"),
        bcrypt: hsh::algorithms::bcrypt::BcryptParams::new(4),
        scrypt: hsh::algorithms::scrypt::ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        },
    }
}

fn reference_hash() -> &'static str {
    static REF: OnceLock<String> = OnceLock::new();
    REF.get_or_init(|| {
        hsh::api::hash(&bcrypt_test_policy(), REFERENCE_PASSWORD)
            .expect("reference hash must succeed")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(candidate) = std::str::from_utf8(data) else {
        return;
    };
    let stored = reference_hash();
    let _ = hsh::api::verify_and_upgrade(&bcrypt_test_policy(), candidate, stored);
});
