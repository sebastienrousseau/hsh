#[cfg(test)]
mod tests {
    use hsh::models::hash_algorithm::HashAlgorithm;
    use hsh::models::hash::{Hash, HashBuilder, Salt};
    use std::str::FromStr;

    #[test]
    fn test_new_argon2i() {
        let password = "password123";
        let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let hash = Hash::new_argon2i(password, salt.clone()).unwrap();
        assert_eq!(hash.salt, salt);
        assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_new_bcrypt() {
        let password = "password123";
        let cost = 4;
        let hash = Hash::new_bcrypt(password, cost).unwrap();
        assert_eq!(hash.algorithm, HashAlgorithm::Bcrypt);
    }

    #[test]
    fn test_new_scrypt() {
        let password = "password123";
        let salt: Salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let hash = Hash::new_scrypt(password, salt.clone()).unwrap();
        assert_eq!(hash.salt, salt);
        assert_eq!(hash.algorithm, HashAlgorithm::Scrypt);
    }

    #[test]
    fn test_from_hash() {
        let hash_bytes = vec![1, 2, 3, 4];
        let hash = Hash::from_hash(&hash_bytes, "argon2i").unwrap();
        assert_eq!(hash.hash, hash_bytes);
        assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_hash_algorithm_from_str() {
        let algorithm = HashAlgorithm::from_str("argon2i").unwrap();
        assert_eq!(algorithm, HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_hash_builder() {
        let hash = vec![1, 2, 3, 4];
        let salt: Salt = vec![0, 1, 2, 3];
        let algorithm = HashAlgorithm::Argon2i;
        let built_hash = HashBuilder::new()
            .hash(hash.clone())
            .salt(salt.clone())
            .algorithm(algorithm)
            .build()
            .unwrap();

        assert_eq!(built_hash.hash, hash);
        assert_eq!(built_hash.salt, salt);
        assert_eq!(built_hash.algorithm, algorithm);
    }

    // Add more tests such as verification, string representation, etc.
}
