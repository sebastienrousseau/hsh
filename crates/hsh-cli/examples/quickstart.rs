// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Library-level demonstration of what `hsh-cli` does under the hood.
//! The CLI itself is a binary (run `hsh --help`); this example is the
//! programmatic shape so you can see the building blocks.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-cli --example quickstart
//! ```

use hsh::{Policy, api};

fn main() {
    let policy = Policy::owasp_minimum_2025();
    let stored = api::hash(&policy, "demo-password").unwrap();

    println!("# hsh hash");
    println!("{stored}");
    println!();

    println!("# hsh verify -H '<stored>'");
    let (outcome, _) =
        api::verify_and_upgrade(&policy, "demo-password", &stored)
            .unwrap();
    if outcome.is_valid() {
        println!("valid");
    } else {
        println!("invalid");
    }
}
