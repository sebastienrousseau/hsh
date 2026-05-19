// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Rotation simulation: build a 2-version keyset, apply with each,
//! confirm the outputs differ.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-kms --example rotation
//! ```

use hsh_kms::{KeyVersion, LocalPepper, Pepper};

fn main() {
    let pepper = LocalPepper::builder()
        .add(
            KeyVersion::new(1),
            b"v1-pepper-keep-this-32-bytes-ok!".to_vec(),
        )
        .add(
            KeyVersion::new(2),
            b"v2-pepper-keep-this-32-bytes-ok!".to_vec(),
        )
        .current(KeyVersion::new(2))
        .build()
        .unwrap();

    let v1_tag = pepper.apply(KeyVersion::new(1), b"password").unwrap();
    let v2_tag = pepper.apply(KeyVersion::new(2), b"password").unwrap();

    assert_ne!(v1_tag, v2_tag, "rotation must produce distinct tags");
    println!("v1 tag prefix: {}", hex_prefix(&v1_tag));
    println!("v2 tag prefix: {}", hex_prefix(&v2_tag));
    println!("current      : {}", pepper.current());

    // Asking for a version that isn't in the keyset errors cleanly.
    let err =
        pepper.apply(KeyVersion::new(99), b"password").unwrap_err();
    println!("unknown ver  : {err}");
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}
