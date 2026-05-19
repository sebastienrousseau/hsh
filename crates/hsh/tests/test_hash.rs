#![allow(missing_docs)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::models::hash::{Hash, HashBuilder, Salt};
    use hsh::models::hash_algorithm::HashAlgorithm;
    use std::str::FromStr;

    #[test]
    fn test_new_argon2i() {
        let password = "password123";
        let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let hash = Hash::new_argon2i(password, salt.clone()).unwrap();
        assert_eq!(hash.salt(), salt.as_slice());
        assert_eq!(hash.algorithm(), HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_new_bcrypt() {
        let password = "password123";
        let cost = 4;
        let hash = Hash::new_bcrypt(password, cost).unwrap();
        assert_eq!(hash.algorithm(), HashAlgorithm::Bcrypt);
    }

    #[test]
    fn test_new_scrypt() {
        let password = "password123";
        let salt: Salt =
            vec![b's', b'a', b'l', b't', b'1', b'2', b'3', b'4'];
        let hash = Hash::new_scrypt(password, salt.clone()).unwrap();
        assert_eq!(hash.salt(), salt.as_slice());
        assert_eq!(hash.algorithm(), HashAlgorithm::Scrypt);
    }

    #[test]
    fn test_from_hash() {
        let hash_bytes = vec![1, 2, 3, 4];
        let hash = Hash::from_hash(&hash_bytes, "argon2i").unwrap();
        assert_eq!(hash.hash(), hash_bytes.as_slice());
        assert_eq!(hash.algorithm(), HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_hash_algorithm_from_str() {
        let algorithm = HashAlgorithm::from_str("argon2i").unwrap();
        assert_eq!(algorithm, HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_hash_builder() {
        let hash_bytes = vec![1, 2, 3, 4];
        let salt: Salt = vec![0, 1, 2, 3];
        let algorithm = HashAlgorithm::Argon2i;
        let built_hash = HashBuilder::new()
            .hash(hash_bytes.clone())
            .salt(salt.clone())
            .algorithm(algorithm)
            .build()
            .unwrap();

        assert_eq!(built_hash.hash(), hash_bytes.as_slice());
        assert_eq!(built_hash.salt(), salt.as_slice());
        assert_eq!(built_hash.algorithm(), algorithm);
    }
}
