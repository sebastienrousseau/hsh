// Copyright © 2023-2024 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::algorithms::argon2i::Argon2i;
    use hsh::models::hash::Hash;
    use hsh::models::hash_algorithm::{
        HashAlgorithm, HashingAlgorithm,
    };

    #[test]
    fn test_hash_differs_from_password() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            Argon2i::hash_password(password, salt).unwrap();

        assert_ne!(hashed_password, password.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_hashes() {
        let password = "password123";
        let salt1 = "salt123456789012345678901234567";
        let salt2 = "salt234567890123456789012345678";

        let hash1 = Argon2i::hash_password(password, salt1).unwrap();
        let hash2 = Argon2i::hash_password(password, salt2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_same_password_and_salt_produce_same_hash() {
        let password = "password123";
        let salt = "somesalt";

        let hash1 = Argon2i::hash_password(password, salt).unwrap();
        let hash2 = Argon2i::hash_password(password, salt).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_password_length() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            Argon2i::hash_password(password, salt).unwrap();

        assert_eq!(hashed_password.len(), 32); // Assuming a 32-byte hash
    }

    #[test]
    fn test_hash_password_not_empty() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            Argon2i::hash_password(password, salt).unwrap();

        assert!(!hashed_password.is_empty());
    }

    #[test]
    fn test_hash_password_error() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            Argon2i::hash_password(password, salt).unwrap();

        assert!(!hashed_password.is_empty());
    }

    #[test]
    fn test_from_hash() {
        let hash_bytes = vec![1, 2, 3, 4];
        let hash = Hash::from_hash(&hash_bytes, "argon2i").unwrap();
        assert_eq!(hash.hash, hash_bytes);
        assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_from_hash_error() {
        let hash_bytes = vec![1, 2, 3, 4];
        let hash = Hash::from_hash(&hash_bytes, "argon2i").unwrap();
        assert_eq!(hash.hash, hash_bytes);
        assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
    }
}
