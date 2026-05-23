#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Coverage tests for `crates/hsh/src/error.rs` — the structured
//! `Error` enum, `HashingError` wrapper, `DecodeError` sub-enum, and
//! every `From<_>` conversion. These tests don't exercise the
//! cryptographic paths; they pin down the *error surface* itself so
//! downstream `match` blocks and `From` chains stay stable.

use hsh::error::{DecodeError, Error, HashingErrorKind};

// ---------------------------------------------------------------------------
// Display impls — every variant must produce non-empty, context-bearing text.
// ---------------------------------------------------------------------------

#[test]
fn unsupported_algorithm_display() {
    let e = Error::UnsupportedAlgorithm("foo".into());
    assert_eq!(format!("{e}"), "unsupported hash algorithm: foo");
}

#[test]
fn invalid_hash_string_display() {
    let e = Error::InvalidHashString("bad PHC".into());
    assert_eq!(format!("{e}"), "invalid hash string: bad PHC");
}

#[test]
fn invalid_parameter_display() {
    let e = Error::InvalidParameter("cost out of range".into());
    assert_eq!(format!("{e}"), "invalid parameter: cost out of range");
}

#[test]
fn invalid_password_display() {
    let e = Error::InvalidPassword("too long".into());
    assert_eq!(format!("{e}"), "password rejected: too long");
}

#[test]
fn invalid_salt_display() {
    let e = Error::InvalidSalt("not base64".into());
    assert_eq!(format!("{e}"), "invalid salt: not base64");
}

#[test]
fn verification_display() {
    let e = Error::Verification("stored corrupt".into());
    assert_eq!(format!("{e}"), "verification failed: stored corrupt");
}

#[test]
fn invalid_policy_display() {
    let e = Error::InvalidPolicy("primary missing".into());
    assert_eq!(format!("{e}"), "invalid policy: primary missing");
}

// ---------------------------------------------------------------------------
// HashingError + HashingErrorKind
// ---------------------------------------------------------------------------

#[test]
fn hashing_error_kind_display_covers_every_variant() {
    assert_eq!(format!("{}", HashingErrorKind::Argon2), "argon2");
    assert_eq!(format!("{}", HashingErrorKind::Bcrypt), "bcrypt");
    assert_eq!(format!("{}", HashingErrorKind::Scrypt), "scrypt");
    assert_eq!(format!("{}", HashingErrorKind::Pbkdf2), "pbkdf2");
    assert_eq!(
        format!("{}", HashingErrorKind::PhcEncoder),
        "phc encoder"
    );
}

#[test]
fn hashing_error_constructor_threads_kind_and_detail() {
    let e =
        Error::hashing(HashingErrorKind::Argon2, "memory cost too low");
    let rendered = format!("{e}");
    assert!(rendered.contains("argon2"));
    assert!(rendered.contains("memory cost too low"));
}

#[test]
fn hashing_error_accepts_owned_string() {
    let detail = String::from("dynamic detail");
    let e = Error::hashing(HashingErrorKind::Bcrypt, detail);
    let rendered = format!("{e}");
    assert!(rendered.contains("bcrypt"));
    assert!(rendered.contains("dynamic detail"));
}

#[test]
fn hashing_error_display_format_is_kind_colon_detail() {
    // HashingError is #[non_exhaustive] — go through the Error::hashing
    // constructor, then unwrap the inner via pattern match.
    let outer =
        Error::hashing(HashingErrorKind::Scrypt, "invalid log_n");
    let Error::Hashing(inner) = outer else {
        unreachable!("constructor returns Error::Hashing variant");
    };
    assert_eq!(format!("{inner}"), "scrypt: invalid log_n");
    assert_eq!(inner.kind, HashingErrorKind::Scrypt);
    assert_eq!(inner.detail, "invalid log_n");
}

#[test]
fn hashing_error_kind_equality_and_ord() {
    assert_eq!(HashingErrorKind::Argon2, HashingErrorKind::Argon2);
    assert_ne!(HashingErrorKind::Argon2, HashingErrorKind::Bcrypt);
    let mut kinds = [
        HashingErrorKind::PhcEncoder,
        HashingErrorKind::Argon2,
        HashingErrorKind::Bcrypt,
    ];
    kinds.sort();
    // Argon2 first because the enum order is Argon2 / Bcrypt / Scrypt /
    // Pbkdf2 / PhcEncoder.
    assert_eq!(kinds[0], HashingErrorKind::Argon2);
}

// ---------------------------------------------------------------------------
// DecodeError sub-enum + the Decode wrapper variant
// ---------------------------------------------------------------------------

#[test]
fn decode_utf8_display() {
    let e = DecodeError::Utf8("invalid byte 0xff".into());
    let s = format!("{e}");
    assert!(s.starts_with("utf-8 decode:"));
    assert!(s.contains("invalid byte 0xff"));
}

#[test]
fn decode_base64_display() {
    let e = DecodeError::Base64("invalid padding".into());
    let s = format!("{e}");
    assert!(s.starts_with("base64 decode:"));
}

#[test]
fn decode_json_display() {
    let e = DecodeError::Json("expected `,`".into());
    let s = format!("{e}");
    assert!(s.starts_with("json decode:"));
}

#[test]
fn error_decode_is_transparent_to_inner() {
    // Error::Decode uses `#[error(transparent)]` so its Display passes
    // through to the inner DecodeError's Display.
    let inner = DecodeError::Base64("bad input".into());
    let outer = Error::Decode(inner);
    assert!(format!("{outer}").starts_with("base64 decode:"));
}

// ---------------------------------------------------------------------------
// From<_> conversions — `?` ergonomics from the underlying stdlib /
// dependency errors into hsh::Error.
// ---------------------------------------------------------------------------

#[test]
fn from_utf8_error_wraps_into_decode_utf8() {
    // std::str::from_utf8 on an invalid byte sequence.
    let bad: Vec<u8> = vec![0xff, 0xfe];
    let err = std::str::from_utf8(&bad).unwrap_err();
    let hsh_err: Error = err.into();
    assert!(matches!(hsh_err, Error::Decode(DecodeError::Utf8(_))));
}

#[test]
fn from_base64_decode_error_wraps_into_decode_base64() {
    use base64::{engine::general_purpose, Engine as _};
    let err = general_purpose::STANDARD.decode("@@@").unwrap_err();
    let hsh_err: Error = err.into();
    assert!(matches!(hsh_err, Error::Decode(DecodeError::Base64(_))));
}

#[test]
fn from_serde_json_error_wraps_into_decode_json() {
    let err = serde_json::from_str::<i32>("{").unwrap_err();
    let hsh_err: Error = err.into();
    assert!(matches!(hsh_err, Error::Decode(DecodeError::Json(_))));
}

#[cfg(feature = "pepper")]
#[test]
fn from_pepper_error_wraps_into_pepper_variant() {
    let pe = hsh_kms::PepperError::UnknownVersion(
        hsh_kms::KeyVersion::new(7),
    );
    let hsh_err: Error = pe.into();
    assert!(matches!(hsh_err, Error::Pepper(_)));
    assert!(format!("{hsh_err}").contains("pepper provider:"));
}

// ---------------------------------------------------------------------------
// std::error::Error trait + source chains
// ---------------------------------------------------------------------------

#[test]
fn error_implements_std_error() {
    fn assert_std_error<
        T: std::error::Error + Send + Sync + 'static,
    >() {
    }
    assert_std_error::<Error>();
    assert_std_error::<DecodeError>();
}

#[test]
fn hashing_error_source_chain() {
    // HashingError itself is the leaf — std::error::Error::source returns
    // None because we don't wrap a typed source (we stringify on
    // construction for Clone-ability).
    let outer =
        Error::hashing(HashingErrorKind::Pbkdf2, "iterations < 1");
    let Error::Hashing(inner) = outer else {
        unreachable!();
    };
    let as_err: &dyn std::error::Error = &inner;
    assert!(as_err.source().is_none());
}

// ---------------------------------------------------------------------------
// Clone semantics — critical so error fan-out (tower middleware, retry
// budgets) doesn't need Arc-wrapping.
// ---------------------------------------------------------------------------

#[test]
fn error_clone_preserves_variant_and_payload() {
    let original = Error::InvalidParameter("oops".into());
    let cloned = original.clone();
    assert_eq!(format!("{original}"), format!("{cloned}"));
}

#[test]
fn hashing_error_clone_preserves_kind_and_detail() {
    let outer = Error::hashing(HashingErrorKind::Bcrypt, "cost = 0");
    let Error::Hashing(original) = outer else {
        unreachable!();
    };
    let cloned = original.clone();
    assert_eq!(cloned.kind, HashingErrorKind::Bcrypt);
    assert_eq!(cloned.detail, "cost = 0");
}

#[test]
fn decode_error_clone_round_trip() {
    let original = DecodeError::Json("expected `]`".into());
    let cloned = original.clone();
    assert_eq!(format!("{original}"), format!("{cloned}"));
}

// ---------------------------------------------------------------------------
// Cow<'static, str> dual-mode payload — literals (zero-alloc) AND owned.
// ---------------------------------------------------------------------------

#[test]
fn error_accepts_static_literal_payload() {
    // Literal &'static str into Cow::Borrowed — zero alloc.
    let e = Error::InvalidPassword("static literal".into());
    let payload: &str = match &e {
        Error::InvalidPassword(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(payload, "static literal");
}

#[test]
fn error_accepts_owned_string_payload() {
    let dynamic = format!("computed at runtime: {}", 42);
    let e = Error::InvalidPassword(dynamic.into());
    let payload: &str = match &e {
        Error::InvalidPassword(s) => s,
        _ => unreachable!(),
    };
    assert!(payload.contains("42"));
}

// ---------------------------------------------------------------------------
// Send + Sync — error must traverse thread boundaries cleanly.
// ---------------------------------------------------------------------------

#[test]
fn error_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Error>();
    assert_send_sync::<DecodeError>();
    assert_send_sync::<HashingErrorKind>();
}
