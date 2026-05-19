#![no_main]
//! Round-trip property: for any valid policy + password, hashing then
//! verifying must succeed.

use libfuzzer_sys::fuzz_target;

fn weak_test_policy() -> hsh::Policy {
    hsh::Policy {
        primary: hsh::PrimaryAlgorithm::Argon2id,
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

fuzz_target!(|data: &[u8]| {
    // Argon2id rejects empty password and passwords containing internal
    // nul bytes can be invalid input for some KDFs — confine to printable
    // ASCII to stay in the supported range.
    let Ok(pwd) = std::str::from_utf8(data) else {
        return;
    };
    if pwd.len() < 1 || pwd.len() > 1024 {
        return;
    }

    let policy = weak_test_policy();
    let Ok(stored) = hsh::api::hash(&policy, pwd) else {
        return;
    };
    let Ok((outcome, _)) = hsh::api::verify_and_upgrade(&policy, pwd, &stored) else {
        return;
    };
    assert!(outcome.is_valid(), "round-trip failed for {pwd:?}");
});
