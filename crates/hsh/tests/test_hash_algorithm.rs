#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::models::hash_algorithm::{
        HashAlgorithm, HashingAlgorithm,
    };

    struct DummyAlgorithm;

    impl HashingAlgorithm for DummyAlgorithm {
        fn hash_password(
            _password: &str,
            _salt: &str,
        ) -> hsh::Result<Vec<u8>> {
            Ok(vec![1, 2, 3, 4])
        }
    }

    #[test]
    fn test_hash_algorithm_enum_round_trip_via_display() {
        // The variant order is an implementation detail; we test that the
        // Display form (used in error messages and PHC strings) is stable.
        assert_eq!(format!("{}", HashAlgorithm::Argon2id), "Argon2id");
        assert_eq!(format!("{}", HashAlgorithm::Argon2i), "Argon2i");
        assert_eq!(format!("{}", HashAlgorithm::Argon2d), "Argon2d");
        assert_eq!(format!("{}", HashAlgorithm::Bcrypt), "Bcrypt");
        assert_eq!(format!("{}", HashAlgorithm::Scrypt), "Scrypt");
    }

    #[test]
    fn test_hashing_algorithm_trait() {
        let password = "password123";
        let salt = "salt123";
        let hashed =
            DummyAlgorithm::hash_password(password, salt).unwrap();
        assert_eq!(hashed, vec![1, 2, 3, 4]);
    }
}
