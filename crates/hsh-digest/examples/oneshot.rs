// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Minimal one-shot hash + hex print across every default algorithm.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-digest --example oneshot
//! ```

use hsh_digest::{hash, Algorithm};

fn main() {
    let input = b"hello, world";

    for algo in [
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Blake3,
    ] {
        let digest = hash(algo, input).unwrap();
        println!(
            "{:<10} ({:>2} B) : {}",
            algo.id(),
            digest.len(),
            hex(&digest),
        );
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
