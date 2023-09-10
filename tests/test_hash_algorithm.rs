#[cfg(test)]
mod tests {
    use hsh::models::hash_algorithm::{HashAlgorithm, HashingAlgorithm};

    // Dummy struct to implement HashingAlgorithm for testing
    struct DummyAlgorithm;

    impl HashingAlgorithm for DummyAlgorithm {
        fn hash_password(_password: &str, _salt: &str) -> Result<Vec<u8>, String> {
            Ok(vec![1, 2, 3, 4])  // Dummy logic
        }
    }

    #[test]
    fn test_hash_algorithm_enum() {
        let argon2i = HashAlgorithm::Argon2i;
        let bcrypt = HashAlgorithm::Bcrypt;
        let scrypt = HashAlgorithm::Scrypt;

        assert_eq!(argon2i as i32, 0);
        assert_eq!(bcrypt as i32, 1);
        assert_eq!(scrypt as i32, 2);
    }

    #[test]
    fn test_hashing_algorithm_trait() {
        let password = "password123";
        let salt = "salt123";
        let hashed = DummyAlgorithm::hash_password(password, salt).unwrap();
        assert_eq!(hashed, vec![1, 2, 3, 4]);
    }
}
