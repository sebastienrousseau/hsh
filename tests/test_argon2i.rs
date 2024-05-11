// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::models::hash_algorithm::HashingAlgorithm;

    #[test]
    fn test_hash_differs_from_password() {
        let password = "password123";
        let salt = "somesalt";
        let hashed_password =
            hsh::algorithms::argon2i::Argon2i::hash_password(
                password, salt,
            )
            .unwrap();

        assert_ne!(hashed_password, password.as_bytes());
    }

    #[test]
    fn test_different_salts_produce_different_hashes() {
        let password = "password123";
        let salt1 = "salt123456789012345678901234567";
        let salt2 = "salt234567890123456789012345678";

        let hash1 = hsh::algorithms::argon2i::Argon2i::hash_password(
            password, salt1,
        )
        .unwrap();
        let hash2 = hsh::algorithms::argon2i::Argon2i::hash_password(
            password, salt2,
        )
        .unwrap();

        assert_ne!(hash1, hash2);
    }
}
