// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Demonstrates the fail-closed FIPS contract.
//!
//! `Policy::fips_140_pbkdf2()` returns a policy with
//! `Backend::Fips140Required`. Today the `fips` feature is a
//! forward-compat marker — `Backend::fips_available_in_build()`
//! returns `false`, so `api::hash` refuses to mint anything rather
//! than silently using non-FIPS crypto.
//!
//! Run with:
//! ```text
//! cargo run -p hsh --example fips_policy
//! ```

use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};
use hsh::{api, Backend};

fn main() {
    let policy = Policy::fips_140_pbkdf2();
    println!("Primary           : {:?}", policy.primary());
    println!("Backend           : {:?}", policy.backend());
    println!(
        "FIPS available    : {}",
        Backend::fips_available_in_build()
    );

    // Refused because the build can't satisfy FIPS today.
    let err = api::hash(&policy, "user-pw").unwrap_err();
    println!("api::hash refused : {err}");

    // It would also refuse if a caller tried to combine FIPS with a
    // non-PBKDF2 primary — internal contradiction.
    let contradictory =
        PolicyBuilder::from_preset(&Policy::fips_140_pbkdf2())
            .primary(PrimaryAlgorithm::Argon2id)
            .build()
            .unwrap();
    let err2 = api::hash(&contradictory, "user-pw").unwrap_err();
    println!("Contradiction     : {err2}");
}
