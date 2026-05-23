// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Migration pattern: existing bcrypt hashes verify cleanly, and a
//! successful login transparently upgrades them to Argon2id.
//!
//! Run with:
//! ```text
//! cargo run -p hsh --example migration_from_bcrypt
//! ```

use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{api, Outcome};

fn main() {
    // Step 1: an old bcrypt hash in your database.
    let bcrypt_policy =
        PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
            .primary(PrimaryAlgorithm::Bcrypt)
            .build()
            .unwrap();
    let legacy_bcrypt =
        api::hash(&bcrypt_policy, "user-password").unwrap();
    println!("legacy bcrypt: {legacy_bcrypt}");

    // Step 2: deploy with an Argon2id-primary policy. Existing bcrypt
    // hashes are still accepted on verify.
    let new_policy = Policy::owasp_minimum_2025(); // Argon2id primary
    let outcome = api::verify_and_upgrade(
        &new_policy,
        "user-password",
        &legacy_bcrypt,
    )
    .unwrap();

    assert!(matches!(outcome, Outcome::Valid { rehashed: Some(_) }));
    let upgraded = outcome
        .rehashed()
        .expect("needs_rehash → new PHC")
        .to_owned();
    assert!(upgraded.starts_with("$argon2id$"));
    println!("upgraded     : {upgraded}");

    // Step 3: persist `upgraded` against the user row. The next login
    // reads the Argon2id hash directly with no further rehash needed.
}
