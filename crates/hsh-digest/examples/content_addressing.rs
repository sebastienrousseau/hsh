// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Git-style content addressing — hash a piece of content and use the
//! digest as its identifier. Demonstrates constant-time comparison
//! when looking up a content hash by its expected identifier.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-digest --example content_addressing
//! ```

use std::collections::HashMap;

use hsh_digest::{constant_time_eq, hash, Algorithm};

fn main() {
    // Content-addressed store.
    let mut store: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();

    // Insert some contents.
    for content in [&b"hello"[..], b"world", b"correct horse"] {
        let id = hash(Algorithm::Sha256, content).unwrap();
        println!("store: {} → {} bytes", id_short(&id), content.len());
        let _ = store.insert(id, content.to_vec());
    }

    // Look up a piece of content by its expected hash, with
    // constant-time comparison against the (untrusted) lookup key.
    let untrusted_lookup = hash(Algorithm::Sha256, b"hello").unwrap();
    let matched = store.iter().find(|(stored_id, _)| {
        constant_time_eq(stored_id, &untrusted_lookup)
    });

    match matched {
        Some((_, content)) => {
            println!(
                "found: {:?}",
                std::str::from_utf8(content).unwrap()
            );
        }
        None => println!("not found"),
    }
}

fn id_short(id: &[u8]) -> String {
    id.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
