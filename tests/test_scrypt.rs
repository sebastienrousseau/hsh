// Copyright © 2023-2024 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::models::hash_algorithm::HashingAlgorithm;

    #[test]
    fn test_hash_password_success() {
        let password = "secure_password";
        let salt = "random_salt";

        let result = hsh::algorithms::scrypt::Scrypt::hash_password(
            password, salt,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_same_salt_and_password_produce_same_hash() {
        let password = "password123";
        let salt = "salt123";

        let hash1_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password, salt,
            )
            .unwrap();
        let hash2_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password, salt,
            )
            .unwrap();

        assert_eq!(hash1_result, hash2_result);
    }

    #[test]
    fn test_different_salts_produce_different_hashes() {
        let password = "password123";
        let salt1 = "salt123";
        let salt2 = "another_salt123";

        let hash1_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password, salt1,
            )
            .unwrap();
        let hash2_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password, salt2,
            )
            .unwrap();

        assert_ne!(hash1_result, hash2_result);
    }

    #[test]
    fn test_different_passwords_produce_different_hashes() {
        let password1 = "password123";
        let password2 = "other_password123";
        let salt = "salt123";

        let hash1_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password1, salt,
            )
            .unwrap();
        let hash2_result =
            hsh::algorithms::scrypt::Scrypt::hash_password(
                password2, salt,
            )
            .unwrap();

        assert_ne!(hash1_result, hash2_result);
    }
}
