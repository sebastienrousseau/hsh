// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Demonstrates the three Policy construction paths: preset, builder
//! from preset, and builder from scratch.
//!
//! Run with:
//! ```text
//! cargo run -p hsh --example builder_pattern
//! ```

use hsh::algorithms::pbkdf2::{Pbkdf2Params, Prf};
use hsh::policy::{Policy, PolicyBuilder, PrimaryAlgorithm};

fn main() {
    // 1. Preset — most common path.
    let preset = Policy::owasp_minimum_2025();
    println!("Preset primary    : {:?}", preset.primary());

    // 2. Builder from preset — overrides selected fields.
    let overridden =
        PolicyBuilder::from_preset(&Policy::owasp_minimum_2025())
            .primary(PrimaryAlgorithm::Pbkdf2)
            .pbkdf2(Pbkdf2Params {
                prf: Prf::Sha512,
                iterations: 210_000,
                dk_len: 32,
            })
            .build()
            .unwrap();
    println!(
        "Overridden primary: {:?}, iters: {}",
        overridden.primary(),
        overridden.pbkdf2_params().iterations,
    );

    // 3. Builder from scratch — must set `primary`.
    let scratch = PolicyBuilder::new()
        .primary(PrimaryAlgorithm::Scrypt)
        .build()
        .unwrap();
    println!("Scratch primary   : {:?}", scratch.primary());

    // Missing `primary` errors.
    let err = PolicyBuilder::new().build().unwrap_err();
    println!("Missing primary   : {err}");
}
