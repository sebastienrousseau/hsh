// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Password hashing algorithm wrappers built on the RustCrypto stack.

/// Argon2 family — `Argon2id` (recommended), `Argon2i`, `Argon2d`.
pub mod argon2id;

/// Re-export of the Argon2i marker for backwards compatibility with the
/// v0.0.x module layout. Deprecated — use [`argon2id::Argon2id`] instead.
pub mod argon2i {
    #[deprecated(
        since = "0.0.9",
        note = "Argon2i is verify-only for legacy hashes — use `crate::algorithms::argon2id::Argon2id` for new hashes."
    )]
    pub use super::argon2id::Argon2i;
}

/// Bcrypt with the 72-byte safety rail enforced.
pub mod bcrypt;

/// PBKDF2-HMAC-SHA-256 / SHA-512 — the only KDF with a FIPS 140-3
/// validated implementation today (via the `fips` feature).
pub mod pbkdf2;

/// Scrypt with configurable parameters (default = OWASP-2025 minimum).
pub mod scrypt;
