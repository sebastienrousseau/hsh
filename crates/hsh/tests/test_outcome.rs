#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage tests for the `Outcome` enum's helper methods. The
//! enum's wire shape itself is covered by the algorithm-specific
//! `test_api.rs` / `test_pepper.rs` integration tests; this file
//! pins down the boolean accessors and the `rehashed` projections.

use hsh::Outcome;

#[test]
fn valid_no_rehash_is_valid_and_no_rehash() {
    let o = Outcome::Valid { rehashed: None };
    assert!(o.is_valid());
    assert!(!o.needs_rehash());
}

#[test]
fn valid_with_rehash_is_valid_and_needs_rehash() {
    let o = Outcome::Valid {
        rehashed: Some("$argon2id$…".to_owned()),
    };
    assert!(o.is_valid());
    assert!(o.needs_rehash());
}

#[test]
fn invalid_is_neither_valid_nor_needs_rehash() {
    let o = Outcome::Invalid;
    assert!(!o.is_valid());
    assert!(!o.needs_rehash());
}

#[test]
fn rehashed_returns_str_slice_when_present() {
    let o = Outcome::Valid {
        rehashed: Some("payload".to_owned()),
    };
    assert_eq!(o.rehashed(), Some("payload"));
}

#[test]
fn rehashed_returns_none_when_no_payload() {
    let o = Outcome::Valid { rehashed: None };
    assert_eq!(o.rehashed(), None);
}

#[test]
fn rehashed_returns_none_on_invalid() {
    let o = Outcome::Invalid;
    assert_eq!(o.rehashed(), None);
}

#[test]
fn into_rehashed_consumes_and_yields_owned_string() {
    let o = Outcome::Valid {
        rehashed: Some("consumed".to_owned()),
    };
    let s = o.into_rehashed();
    assert_eq!(s.as_deref(), Some("consumed"));
}

#[test]
fn into_rehashed_yields_none_on_no_rehash() {
    let o = Outcome::Valid { rehashed: None };
    assert_eq!(o.into_rehashed(), None);
}

#[test]
fn into_rehashed_yields_none_on_invalid() {
    let o = Outcome::Invalid;
    assert_eq!(o.into_rehashed(), None);
}

#[test]
fn outcome_clone_round_trips_invalid() {
    let original = Outcome::Invalid;
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn outcome_clone_round_trips_valid_with_payload() {
    let original = Outcome::Valid {
        rehashed: Some("phc".to_owned()),
    };
    let cloned = original.clone();
    assert_eq!(original, cloned);
}

#[test]
fn outcome_partialeq_distinguishes_variants() {
    let valid_a = Outcome::Valid { rehashed: None };
    let valid_b = Outcome::Valid {
        rehashed: Some("x".to_owned()),
    };
    let invalid = Outcome::Invalid;

    assert_ne!(valid_a, valid_b);
    assert_ne!(valid_a, invalid);
    assert_ne!(valid_b, invalid);
}

#[test]
fn outcome_debug_format_includes_variant_name() {
    let o = Outcome::Valid {
        rehashed: Some("hash".to_owned()),
    };
    let d = format!("{o:?}");
    assert!(d.contains("Valid"));
    assert!(d.contains("rehashed"));
}

#[test]
fn outcome_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Outcome>();
}
