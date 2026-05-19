// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Minimal hash + verify in 10 LOC. The simplest entry point for the
//! `hsh` library.
//!
//! Run with:
//! ```text
//! cargo run -p hsh --example quickstart
//! ```

use hsh::{api, Outcome, Policy};

fn main() {
    let policy = Policy::owasp_minimum_2025();
    let stored =
        api::hash(&policy, "correct horse battery staple").unwrap();
    println!("stored: {stored}");

    let (outcome, _) = api::verify_and_upgrade(
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
    println!("verified: valid");
}
