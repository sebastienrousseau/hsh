#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage tests for `hsh-digest` paths the KAT suite doesn't exercise.

use hsh_digest::{
    constant_time_eq, hash, Algorithm, DigestError, Hasher,
};

#[test]
fn algorithm_ids_are_stable() {
    assert_eq!(Algorithm::Sha256.id(), "sha256");
    assert_eq!(Algorithm::Sha384.id(), "sha384");
    assert_eq!(Algorithm::Sha512.id(), "sha512");
    assert_eq!(Algorithm::Sha3_256.id(), "sha3-256");
    assert_eq!(Algorithm::Sha3_384.id(), "sha3-384");
    assert_eq!(Algorithm::Sha3_512.id(), "sha3-512");
    assert_eq!(Algorithm::Blake3.id(), "blake3");
}

#[test]
fn algorithm_output_lengths_are_stable() {
    assert_eq!(Algorithm::Sha256.output_len(), 32);
    assert_eq!(Algorithm::Sha384.output_len(), 48);
    assert_eq!(Algorithm::Sha512.output_len(), 64);
    assert_eq!(Algorithm::Sha3_256.output_len(), 32);
    assert_eq!(Algorithm::Sha3_384.output_len(), 48);
    assert_eq!(Algorithm::Sha3_512.output_len(), 64);
    assert_eq!(Algorithm::Blake3.output_len(), 32);
}

#[test]
fn hasher_reports_its_algorithm() {
    for algo in [
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Blake3,
    ] {
        let h = Hasher::new(algo).unwrap();
        assert_eq!(h.algorithm(), algo);
    }
}

#[test]
fn hasher_debug_does_not_leak_state() {
    let h = Hasher::new(Algorithm::Sha256).unwrap();
    let dbg = format!("{h:?}");
    assert!(dbg.contains("Sha256"));
    assert!(!dbg.contains("input"));
}

#[test]
fn empty_input_one_shot() {
    let digest = hash(Algorithm::Blake3, b"").unwrap();
    assert_eq!(digest.len(), 32);
}

#[test]
fn streaming_zero_updates_equals_empty_one_shot() {
    let one_shot = hash(Algorithm::Sha256, b"").unwrap();
    let streamed = Hasher::new(Algorithm::Sha256).unwrap().finalize();
    assert_eq!(one_shot, streamed);
}

#[test]
fn constant_time_eq_distinguishes_lengths() {
    assert!(!constant_time_eq(b"", b"a"));
    assert!(!constant_time_eq(b"abc", b"abcd"));
}

#[test]
fn constant_time_eq_empty_slices_match() {
    assert!(constant_time_eq(b"", b""));
}

#[test]
fn digest_error_display_is_informative() {
    let err = DigestError::Unavailable("foo");
    let msg = format!("{err}");
    assert!(msg.contains("foo"));
}
