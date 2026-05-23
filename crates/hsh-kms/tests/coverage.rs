#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage tests for `hsh-kms` surface beyond the inline #[cfg(test)]
//! module in lib.rs.

use hsh_kms::{KeyVersion, LocalPepper, Pepper, PepperError};

fn key32(prefix: &str) -> Vec<u8> {
    let mut bytes = prefix.as_bytes().to_vec();
    while bytes.len() < 32 {
        bytes.push(b'x');
    }
    bytes
}

// ---------------------------------------------------------------- KeyVersion
#[test]
fn key_version_new_and_get() {
    let v = KeyVersion::new(42);
    assert_eq!(v.get(), 42);
}

#[test]
fn key_version_default_is_one() {
    assert_eq!(KeyVersion::default(), KeyVersion::new(1));
}

#[test]
fn key_version_ord_round_trip() {
    let a = KeyVersion::new(1);
    let b = KeyVersion::new(2);
    assert!(a < b);
    assert!(b > a);
}

#[test]
fn key_version_display() {
    assert_eq!(format!("{}", KeyVersion::new(7)), "7");
}

// ---------------------------------------------------------------- LocalPepper
#[test]
fn local_pepper_versions_returns_sorted_set() {
    let p = LocalPepper::builder()
        .add(KeyVersion::new(3), key32("v3"))
        .add(KeyVersion::new(1), key32("v1"))
        .add(KeyVersion::new(2), key32("v2"))
        .current(KeyVersion::new(3))
        .build()
        .unwrap();

    let versions = p.versions();
    assert_eq!(
        versions,
        vec![
            KeyVersion::new(1),
            KeyVersion::new(2),
            KeyVersion::new(3)
        ]
    );
}

#[test]
fn local_pepper_debug_does_not_leak_keys() {
    let p = LocalPepper::builder()
        .add(KeyVersion::new(1), key32("super-secret-pepper-bytes"))
        .build()
        .unwrap();
    let dbg = format!("{p:?}");
    assert!(dbg.contains("LocalPepper"));
    assert!(dbg.contains("versions"));
    assert!(!dbg.contains("super-secret-pepper"));
}

#[test]
fn pepper_apply_is_deterministic() {
    let p = LocalPepper::builder()
        .add(KeyVersion::new(1), key32("key-1"))
        .build()
        .unwrap();
    let tag_a = p.apply(KeyVersion::new(1), b"password").unwrap();
    let tag_b = p.apply(KeyVersion::new(1), b"password").unwrap();
    assert_eq!(tag_a, tag_b, "HMAC must be deterministic");
}

#[test]
fn pepper_apply_distinguishes_different_passwords() {
    let p = LocalPepper::builder()
        .add(KeyVersion::new(1), key32("key-1"))
        .build()
        .unwrap();
    let a = p.apply(KeyVersion::new(1), b"password").unwrap();
    let b = p.apply(KeyVersion::new(1), b"different").unwrap();
    assert_ne!(a, b);
}

// ---------------------------------------------------------------- PepperError
#[test]
fn pepper_error_display_includes_context() {
    let err = PepperError::UnknownVersion(KeyVersion::new(99));
    assert!(format!("{err}").contains("99"));

    let err = PepperError::EmptyKeyset;
    assert!(!format!("{err}").is_empty());

    let err = PepperError::KeyTooShort {
        version: KeyVersion::new(1),
        actual: 8,
        minimum: 16,
    };
    let msg = format!("{err}");
    assert!(msg.contains("8"));
    assert!(msg.contains("16"));

    let err = PepperError::Backend("backend broke".into());
    assert!(format!("{err}").contains("backend broke"));
}

// ---------------------------------------------------------------- Builder error paths
#[test]
fn local_pepper_builder_rejects_short_key() {
    let r = LocalPepper::builder()
        .add(KeyVersion::new(1), b"short".to_vec())
        .build();
    assert!(matches!(r, Err(PepperError::KeyTooShort { .. })));
}

#[test]
fn local_pepper_builder_rejects_empty_keyset() {
    let r = LocalPepper::builder().build();
    assert!(matches!(r, Err(PepperError::EmptyKeyset)));
}

#[test]
fn local_pepper_builder_rejects_current_not_in_keyset() {
    let r = LocalPepper::builder()
        .add(KeyVersion::new(1), key32("k1"))
        .current(KeyVersion::new(99))
        .build();
    assert!(matches!(r, Err(PepperError::UnknownVersion(_))));
}

// ---------------------------------------------------------------- Pepper trait
// These three relocated from the historical inline `mod tests` in src/lib.rs.
// CodeQL's `rust/hard-coded-cryptographic-value` heuristic flagged the
// fixture byte-literals reaching `Pepper::apply` from inside `src/`;
// `tests/` is covered by the path-exclusion in `.github/codeql/codeql-config.yml`.
fn fixture() -> LocalPepper {
    LocalPepper::builder()
        .add(KeyVersion::new(1), key32("v1"))
        .add(KeyVersion::new(2), key32("v2"))
        .current(KeyVersion::new(2))
        .build()
        .unwrap()
}

#[test]
fn pepper_apply_returns_32_bytes() {
    let p = fixture();
    let tag = p
        .apply(KeyVersion::new(1), b"deterministic-test-input")
        .unwrap();
    assert_eq!(tag.len(), 32);
}

#[test]
fn pepper_different_versions_produce_different_tags() {
    let p = fixture();
    let a = p
        .apply(KeyVersion::new(1), b"deterministic-test-input")
        .unwrap();
    let b = p
        .apply(KeyVersion::new(2), b"deterministic-test-input")
        .unwrap();
    assert_ne!(a, b);
}

#[test]
fn pepper_unknown_version_errors() {
    let p = fixture();
    let err = p
        .apply(KeyVersion::new(99), b"deterministic-test-input")
        .unwrap_err();
    assert!(matches!(err, PepperError::UnknownVersion(_)));
}
