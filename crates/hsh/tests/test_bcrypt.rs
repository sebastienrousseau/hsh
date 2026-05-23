#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::algorithms::bcrypt::Bcrypt;
    use hsh::models::hash::Hash;
    use hsh::models::hash_algorithm::{
        HashAlgorithm, HashingAlgorithm,
    };
    use hsh::Error;

    #[test]
    fn test_hash_differs_from_password() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            Bcrypt::hash_password(password, salt).unwrap();

        assert_ne!(hashed_password, password.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_hashes() {
        let password = "password123";
        let salt1 = "salt1";
        let salt2 = "salt2";

        let hash1 = Bcrypt::hash_password(password, salt1).unwrap();
        let hash2 = Bcrypt::hash_password(password, salt2).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_hashing_error() {
        let password = "password123";
        let invalid_cost: u32 = 1;
        let result = bcrypt::hash(password, invalid_cost);
        assert!(result.is_err());
    }

    #[test]
    fn test_new_bcrypt() {
        let password = "password123";
        let cost: u32 = 4; // low cost for fast test
        let hash = Hash::new_bcrypt(password, cost).unwrap();

        assert_eq!(hash.algorithm(), HashAlgorithm::Bcrypt);
        assert!(!hash.hash().is_empty());
        assert_eq!(hash.salt().len(), 0);
    }

    #[test]
    fn test_new_bcrypt_error() {
        let password = "password123";
        let invalid_cost: u32 = 0;
        let result = Hash::new_bcrypt(password, invalid_cost);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_hash() {
        let hash_bytes = vec![1, 2, 3, 4];
        let hash = Hash::from_hash(&hash_bytes, "bcrypt").unwrap();
        assert_eq!(hash.hash(), hash_bytes.as_slice());
        assert_eq!(hash.algorithm(), HashAlgorithm::Bcrypt);
    }

    #[test]
    fn test_from_hash_error() {
        let hash_bytes = vec![1, 2, 3, 4];
        let err = Hash::from_hash(&hash_bytes, "invalid").unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedAlgorithm(ref a) if a == "invalid")
        );
    }

    #[test]
    fn test_verify_bcrypt() {
        let password = "password123";
        let hash = Hash::new_bcrypt(password, 4).unwrap();

        assert!(hash.verify(password).unwrap());
        assert!(!hash.verify("wrong_password").unwrap());
    }
}
