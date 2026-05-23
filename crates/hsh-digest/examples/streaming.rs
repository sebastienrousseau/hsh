// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Incremental hashing — feed bytes in chunks, finalize once.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-digest --example streaming
//! ```

use hsh_digest::{hash, Algorithm, Hasher};

fn main() {
    let chunks: &[&[u8]] =
        &[b"the quick brown fox ", b"jumps over ", b"the lazy dog"];
    let combined: Vec<u8> = chunks.concat();

    // Streaming via update/finalize.
    let mut h = Hasher::new(Algorithm::Blake3).unwrap();
    for chunk in chunks {
        h.update(chunk);
    }
    let streaming_digest = h.finalize();

    // One-shot for comparison.
    let oneshot_digest = hash(Algorithm::Blake3, &combined).unwrap();

    assert_eq!(streaming_digest, oneshot_digest, "must be identical");
    println!("streaming digest matches one-shot: ✓");
    println!("digest length     : {} bytes", streaming_digest.len());
}
