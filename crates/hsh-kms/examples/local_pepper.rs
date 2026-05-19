// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT
#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Minimal `LocalPepper` build + apply.
//!
//! Run with:
//! ```text
//! cargo run -p hsh-kms --example local_pepper
//! ```

use hsh_kms::{KeyVersion, LocalPepper, Pepper};

fn main() {
    let pepper = LocalPepper::builder()
        .add(
            KeyVersion::new(1),
            b"v1-server-pepper-32-bytes-min!!!".to_vec(),
        )
        .current(KeyVersion::new(1))
        .build()
        .unwrap();

    let tag =
        pepper.apply(KeyVersion::new(1), b"correct horse").unwrap();
    println!("tag length    : {} bytes", tag.len());
    println!("current ver   : {}", pepper.current());
    println!("known versions: {:?}", pepper.versions());
}
