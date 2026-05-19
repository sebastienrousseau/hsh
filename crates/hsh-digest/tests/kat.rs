#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Known-Answer-Test vectors for `hsh-digest`.
//!
//! Vectors are taken from:
//!
//! - **SHA-2**: NIST CAVP — FIPS 180-4 byte-test vectors
//!   (`SHAVS Byte Test Vectors`).
//! - **SHA-3**: NIST CAVP — FIPS 202 byte-test vectors
//!   (`SHA3VS Byte Test Vectors`).
//! - **BLAKE3**: project test vectors at
//!   `blake3-team/BLAKE3/test_vectors`.

use hsh_digest::{hash, Algorithm, Hasher};

/// SHA-256 of the empty string. NIST CAVP.
#[cfg(feature = "sha2")]
#[test]
fn sha256_empty() {
    let h = hash(Algorithm::Sha256, b"").unwrap();
    assert_eq!(
        hex::encode(&h),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
}

/// SHA-256("abc"). NIST CAVP standard vector.
#[cfg(feature = "sha2")]
#[test]
fn sha256_abc() {
    let h = hash(Algorithm::Sha256, b"abc").unwrap();
    assert_eq!(
        hex::encode(&h),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
}

/// SHA-384("abc"). NIST CAVP.
#[cfg(feature = "sha2")]
#[test]
fn sha384_abc() {
    let h = hash(Algorithm::Sha384, b"abc").unwrap();
    assert_eq!(
        hex::encode(&h),
        "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    );
}

/// SHA-512("abc"). NIST CAVP.
#[cfg(feature = "sha2")]
#[test]
fn sha512_abc() {
    let h = hash(Algorithm::Sha512, b"abc").unwrap();
    assert_eq!(
        hex::encode(&h),
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );
}

/// SHA3-256 of the empty string. NIST FIPS 202.
#[cfg(feature = "sha3")]
#[test]
fn sha3_256_empty() {
    let h = hash(Algorithm::Sha3_256, b"").unwrap();
    assert_eq!(
        hex::encode(&h),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    );
}

/// SHA3-256("abc"). NIST FIPS 202.
#[cfg(feature = "sha3")]
#[test]
fn sha3_256_abc() {
    let h = hash(Algorithm::Sha3_256, b"abc").unwrap();
    assert_eq!(
        hex::encode(&h),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    );
}

/// SHA3-512("abc"). NIST FIPS 202.
#[cfg(feature = "sha3")]
#[test]
fn sha3_512_abc() {
    let h = hash(Algorithm::Sha3_512, b"abc").unwrap();
    assert_eq!(
        hex::encode(&h),
        "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    );
}

/// BLAKE3 of the empty string. From the BLAKE3 test vectors.
#[cfg(feature = "blake3")]
#[test]
fn blake3_empty() {
    let h = hash(Algorithm::Blake3, b"").unwrap();
    assert_eq!(
        hex::encode(&h),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
}

/// BLAKE3 of the all-zeros 1-byte input.
#[cfg(feature = "blake3")]
#[test]
fn blake3_single_zero_byte() {
    let h = hash(Algorithm::Blake3, &[0]).unwrap();
    assert_eq!(
        hex::encode(&h),
        "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
    );
}

/// Streaming API must produce the same digest as one-shot.
#[cfg(feature = "sha2")]
#[test]
fn streaming_matches_one_shot_sha256() {
    let one_shot = hash(Algorithm::Sha256, b"hello, world").unwrap();
    let mut h = Hasher::new(Algorithm::Sha256).unwrap();
    h.update(b"hello, ");
    h.update(b"world");
    let streaming = h.finalize();
    assert_eq!(one_shot, streaming);
}

/// Streaming API for BLAKE3 — many small updates equal one large input.
#[cfg(feature = "blake3")]
#[test]
fn streaming_matches_one_shot_blake3() {
    let one_shot = hash(Algorithm::Blake3, &[0xAB; 256]).unwrap();
    let mut h = Hasher::new(Algorithm::Blake3).unwrap();
    for chunk in
        [&[0xAB; 64][..], &[0xAB; 64], &[0xAB; 64], &[0xAB; 64]]
    {
        h.update(chunk);
    }
    assert_eq!(one_shot, h.finalize());
}

/// Output length agrees with `Algorithm::output_len()`.
#[cfg(all(feature = "sha2", feature = "sha3", feature = "blake3"))]
#[test]
fn output_len_advertised_correctly() {
    for algo in [
        Algorithm::Sha256,
        Algorithm::Sha384,
        Algorithm::Sha512,
        Algorithm::Sha3_256,
        Algorithm::Sha3_384,
        Algorithm::Sha3_512,
        Algorithm::Blake3,
    ] {
        let h = hash(algo, b"probe").unwrap();
        assert_eq!(
            h.len(),
            algo.output_len(),
            "{:?} length mismatch",
            algo
        );
    }
}

#[test]
fn constant_time_eq_matches_logical_eq() {
    assert!(hsh_digest::constant_time_eq(b"abc", b"abc"));
    assert!(!hsh_digest::constant_time_eq(b"abc", b"abd"));
    assert!(!hsh_digest::constant_time_eq(b"abc", b"abcd"));
}
