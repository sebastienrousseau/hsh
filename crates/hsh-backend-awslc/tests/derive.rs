// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Validation tests for the AWS-LC FIPS PBKDF2 derive wrapper.

use hsh_backend_awslc::{pbkdf2_derive, DeriveError, Prf};

#[test]
fn rfc6070_sha256_test_vector_1() {
    // From the RustCrypto/pbkdf2 test suite (RFC 6070-style vectors
    // re-derived for SHA-256 since RFC 6070 itself targets SHA-1).
    // Verifies that the AWS-LC output matches the pure-Rust output for
    // a known fixed input.
    let out = pbkdf2_derive(b"password", b"salt", Prf::Sha256, 1, 32)
        .unwrap();
    let expected: [u8; 32] = [
        0x12, 0x0f, 0xb6, 0xcf, 0xfc, 0xf8, 0xb3, 0x2c, 0x43, 0xe7,
        0x22, 0x52, 0x56, 0xc4, 0xf8, 0x37, 0xa8, 0x65, 0x48, 0xc9,
        0x2c, 0xcc, 0x35, 0x48, 0x08, 0x05, 0x98, 0x7c, 0xb7, 0x0b,
        0xe1, 0x7b,
    ];
    assert_eq!(
        out, expected,
        "PBKDF2-HMAC-SHA-256 RFC vector mismatch"
    );
}

#[test]
fn rfc6070_sha256_2_iterations() {
    let out = pbkdf2_derive(b"password", b"salt", Prf::Sha256, 2, 32)
        .unwrap();
    let expected: [u8; 32] = [
        0xae, 0x4d, 0x0c, 0x95, 0xaf, 0x6b, 0x46, 0xd3, 0x2d, 0x0a,
        0xdf, 0xf9, 0x28, 0xf0, 0x6d, 0xd0, 0x2a, 0x30, 0x3f, 0x8e,
        0xf3, 0xc2, 0x51, 0xdf, 0xd6, 0xe2, 0xd8, 0x5a, 0x95, 0x47,
        0x4c, 0x43,
    ];
    assert_eq!(
        out, expected,
        "PBKDF2-HMAC-SHA-256 2-iter vector mismatch"
    );
}

#[test]
fn sha512_smoke() {
    // No RFC vector for SHA-512 PBKDF2 in the same form, so this is a
    // smoke test confirming: (a) the SHA-512 routing works, (b) output
    // length is honoured, (c) deterministic re-derivation.
    let out1 =
        pbkdf2_derive(b"password", b"NaCl", Prf::Sha512, 1000, 64)
            .unwrap();
    let out2 =
        pbkdf2_derive(b"password", b"NaCl", Prf::Sha512, 1000, 64)
            .unwrap();
    assert_eq!(out1.len(), 64);
    assert_eq!(out1, out2);
    // Different salt produces different output.
    let out3 =
        pbkdf2_derive(b"password", b"NaCl2", Prf::Sha512, 1000, 64)
            .unwrap();
    assert_ne!(out1, out3);
}

#[test]
fn dk_len_is_honoured() {
    for &len in &[1usize, 16, 32, 48, 64, 128] {
        let out =
            pbkdf2_derive(b"password", b"salt", Prf::Sha256, 1000, len)
                .unwrap();
        assert_eq!(out.len(), len, "dk_len {len} not honoured");
    }
}

#[test]
fn zero_iterations_rejected() {
    let err = pbkdf2_derive(b"password", b"salt", Prf::Sha256, 0, 32);
    assert!(matches!(err, Err(DeriveError::IterationsZero)));
}

#[test]
fn zero_dk_len_rejected() {
    let err = pbkdf2_derive(b"password", b"salt", Prf::Sha256, 1, 0);
    assert!(matches!(err, Err(DeriveError::DkLenZero)));
}

#[test]
fn fips_routing_compiled_in_is_const_true() {
    assert!(hsh_backend_awslc::fips_routing_compiled_in());
}
