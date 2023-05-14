// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::*;

    #[test]
    fn test_new() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "argon2i";

        let hash = Hash::new(password, salt, algo).unwrap();

        assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
        assert_eq!(hash.salt, salt.as_bytes().to_vec());
    }

    #[test]
    fn test_verify() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "argon2i";

        let hash = Hash::new(password, salt, algo).unwrap();

        assert!(hash.verify(password).unwrap());
        assert!(!hash.verify("wrongpassword").unwrap());
    }

    #[test]
    fn test_from_string() {
        // You'll need to provide a valid hash string here for this test
        let hash_string = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

        let hash = Hash::from_string(hash_string);

        match hash {
            Ok(hash) => {
                // Assert that the hash, salt, and algorithm are as expected
                assert_eq!(hash.algorithm, HashAlgorithm::Argon2i);
            }
            Err(e) => {
                panic!("Failed to parse hash string: {}", e);
            }
        }
    }

    #[test]
    fn test_generate_salt() {
        let algo = "argon2i";

        let salt = Hash::generate_salt(algo).unwrap();

        // Assert that the salt is of the correct length and format
        assert_eq!(salt.len(), 16);
    }
    #[test]
    fn test_argon2i_hashing() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "argon2i";

        let hash = Hash::new(password, salt, algo).unwrap();

        assert!(hash.verify(password).unwrap());
        assert!(!hash.verify("wrongpassword").unwrap());
    }

    #[test]
    fn test_bcrypt_hashing() {
        let password = "password123";
        let salt = Hash::generate_salt("bcrypt").unwrap();
        let algo = "bcrypt";

        let hash = Hash::new(password, &salt, algo).unwrap();

        assert!(hash.verify(password).unwrap());
        assert!(!hash.verify("wrongpassword").unwrap());
    }

    #[test]
    fn test_scrypt_hashing() {
        let password = "password123";
        let salt = Hash::generate_salt("scrypt").unwrap();
        let algo = "scrypt";

        let hash = Hash::new(password, &salt, algo).unwrap();

        assert!(hash.verify(password).unwrap());
        assert!(!hash.verify("wrongpassword").unwrap());
    }

    #[test]
    fn test_set_password() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "argon2i";

        let mut hash = Hash::new(password, salt, algo).unwrap();

        let new_password = "newpassword123";
        hash.set_password(new_password, salt, algo).unwrap();

        assert!(hash.verify(new_password).unwrap());
        assert!(!hash.verify(password).unwrap());
    }

    #[test]
    fn test_invalid_algorithm() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "invalid_algo";

        let hash = Hash::new(password, salt, algo);

        assert!(hash.is_err());
    }

    #[test]
    fn test_short_password() {
        let password = "short";
        let salt = "somesalt";
        let algo = "argon2i";

        let hash = Hash::new(password, salt, algo);

        assert!(hash.is_err());
    }
}
