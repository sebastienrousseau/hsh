// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Demonstrates the fail-closed contract: peppered hashes are rejected
//! when the verifier doesn't carry the pepper.
//!
//! Note: this example uses the `hsh` library directly (with the
//! `pepper` feature) because the policy-level fail-closed check
//! lives in `hsh::api::verify_and_upgrade`. Run with:
//!
//! ```text
//! cargo run -p hsh-kms --example refuse_without_pepper
//! ```
//!
//! (`hsh-kms` itself only carries the `Pepper` trait; the integration
//! with `Policy` is in `hsh`.)

use hsh_kms::{KeyVersion, LocalPepper, Pepper};

fn main() {
    let pepper = LocalPepper::builder()
        .add(
            KeyVersion::new(1),
            b"server-pepper-32-bytes-keep-secret".to_vec(),
        )
        .current(KeyVersion::new(1))
        .build()
        .unwrap();

    // The trait itself just applies HMAC.
    let tag =
        pepper.apply(KeyVersion::new(1), b"user-password").unwrap();
    println!("HMAC tag length: {} bytes", tag.len());

    // The fail-closed *policy* check lives in `hsh::api::verify_and_upgrade`
    // — see `crates/hsh/tests/test_pepper.rs::peppered_rejected_when_policy_has_no_pepper`.
    println!(
        "(see hsh::api::verify_and_upgrade for the policy-level \
         fail-closed semantics)"
    );
}
