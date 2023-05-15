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
    fn test_new_with_unsupported_algo() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "unsupported_algo";

        let hash = Hash::new(password, salt, algo);

        match hash {
            Ok(_) => {
                panic!("Expected an error for unsupported hash algorithm, but got Ok");
            }
            Err(e) => {
                assert_eq!(
                    e,
                    format!("Unsupported hash algorithm: {}", algo)
                );
            }
        }
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
    fn test_from_string_invalid_hash_string() {
        // Provide an invalid hash string
        let invalid_hash_string = "invalid$hash$string";

        let hash = Hash::from_string(invalid_hash_string);

        // Expect an error to be returned
        assert!(hash.is_err());

        // Check the error message
        match hash {
            Err(e) => {
                assert_eq!(e, String::from("Invalid hash string"))
            }
            _ => panic!("Expected Err, got Ok"),
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
    fn test_generate_salt_invalid_algorithm() {
        let invalid_algo = "unsupported_algo";

        let salt = Hash::generate_salt(invalid_algo);

        // Expect an error to be returned
        assert!(salt.is_err());

        // Check the error message
        match salt {
            Err(e) => assert_eq!(
                e,
                format!("Unsupported hash algorithm: {}", invalid_algo)
            ),
            _ => panic!("Expected Err, got Ok"),
        }
    }

    #[test]
    fn test_generate_salt_bcrypt() {
        let algo = "bcrypt";

        let salt = Hash::generate_salt(algo).unwrap();

        // Assert that the salt is of the correct length and format
        assert_eq!(salt.len(), 24); // bcrypt salt will be longer due to base64 encoding
    }

    #[test]
    fn test_generate_salt_scrypt() {
        let algo = "scrypt";

        let salt = Hash::generate_salt(algo).unwrap();

        // Assert that the salt is of the correct length and format
        assert_eq!(salt.len(), 44); // scrypt salt will be longer due to base64 encoding
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

    #[test]
    fn test_algorithm() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let hash = Hash::new(password, salt, algo).unwrap();

        assert_eq!(HashAlgorithm::Bcrypt, hash.algorithm());
    }

    #[test]
    fn test_from_hash() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "scrypt";

        // Generate a hash from the password
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Get the hashed password bytes
        let hashed_password = original_hash.hash;

        // Now try to create a new Hash struct from the hashed password bytes
        let from_hash = Hash::from_hash(&hashed_password, algo);

        // Check that from_hash is Ok
        assert!(from_hash.is_ok());

        // Unwrap the Result and get the Hash struct
        let from_hash = from_hash.unwrap();

        // Check that the algorithm is correct
        assert_eq!(from_hash.algorithm(), HashAlgorithm::Scrypt);

        // Check that the hash is correct
        assert_eq!(from_hash.hash, hashed_password);

        // Check that the salt is empty (since from_hash doesn't set the salt)
        assert_eq!(from_hash.salt, Vec::<u8>::new());
    }

    #[test]
    fn test_from_hash_invalid_algorithm() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "unsupported_algo";

        // Generate a hash from the password
        let original_hash =
            Hash::new(password, salt, "bcrypt").unwrap();

        // Get the hashed password bytes
        let hashed_password = original_hash.hash;

        // Now try to create a new Hash struct from the hashed password bytes
        let from_hash = Hash::from_hash(&hashed_password, algo);

        // Check that from_hash is Err
        assert!(from_hash.is_err());

        // Check the error message
        match from_hash {
            Err(e) => assert_eq!(
                e,
                format!("Unsupported hash algorithm: {}", algo)
            ),
            _ => panic!("Expected Err, got Ok"),
        }
    }

    #[test]
    fn test_hash() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Get the hashed password bytes
        let hashed_password = original_hash.hash.clone();

        // Test the `hash` method
        assert_eq!(original_hash.hash(), &hashed_password);
    }

    #[test]
    fn test_salt() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Convert the salt to bytes for comparison
        let salt_bytes = salt.as_bytes();

        // Test the `salt` method
        assert_eq!(original_hash.salt(), salt_bytes);
    }

    #[test]
    fn test_set_hash() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let mut original_hash =
            Hash::new(password, salt, algo).unwrap();

        // Create a new hash value
        let new_hash = vec![1, 2, 3, 4, 5];

        // Set the hash of the Hash struct to the new value
        original_hash.set_hash(&new_hash);

        // Test that the `hash` method returns the new hash value
        assert_eq!(original_hash.hash(), &new_hash);
    }

    #[test]
    fn test_set_salt() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let mut original_hash =
            Hash::new(password, salt, algo).unwrap();

        // Create a new salt value
        let new_salt = vec![1, 2, 3, 4, 5];

        // Set the salt of the Hash struct to the new value
        original_hash.set_salt(&new_salt);

        // Test that the `salt` method returns the new salt value
        assert_eq!(original_hash.salt(), &new_salt);
    }
    #[test]
    fn test_to_string_representation() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Get the string representation
        let string_repr = original_hash.to_string_representation();

        // Get the expected string representation
        let expected_repr = format!(
            "{}:{}",
            salt,
            original_hash
                .hash()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<String>>()
                .join("")
        );

        assert_eq!(string_repr, expected_repr);
    }
    #[test]
    fn test_hash_display() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Test the Display implementation for Hash
        assert_eq!(
            format!("{}", original_hash),
            format!("Hash {{ hash: {:?} }}", original_hash.hash())
        );
    }

    #[test]
    fn test_hash_algorithm_display() {
        let algo = HashAlgorithm::Bcrypt;

        // Test the Display implementation for HashAlgorithm
        assert_eq!(format!("{}", algo), format!("{:?}", algo));
    }

    #[test]
    fn test_hash_algorithm_from_str() {
        let algo_str = "bcrypt";
        let expected_algo = HashAlgorithm::Bcrypt;

        // Test the FromStr implementation for HashAlgorithm
        assert_eq!(
            algo_str.parse::<HashAlgorithm>().unwrap(),
            expected_algo
        );
    }

    #[test]
    fn test_hash_algorithm_from_str_invalid() {
        let invalid_algo_str = "invalid";

        // Test the FromStr implementation for HashAlgorithm with an invalid string
        assert!(invalid_algo_str.parse::<HashAlgorithm>().is_err());
    }

    #[test]
    fn test_parse() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        // Create a new Hash
        let original_hash = Hash::new(password, salt, algo).unwrap();

        // Convert the Hash to a JSON string
        let hash_json = serde_json::to_string(&original_hash).unwrap();

        // Parse the JSON string back into a Hash
        let parsed_hash = Hash::parse(&hash_json).unwrap();

        // Check that the parsed Hash is equal to the original
        assert_eq!(original_hash, parsed_hash);
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_json = "invalid";

        // Try to parse the invalid JSON string
        assert!(Hash::parse(invalid_json).is_err());
    }

    #[test]
    fn test_parse_algorithm_argon2i() {
        let hash_str = "$argon2i$somehashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert_eq!(algorithm.unwrap(), HashAlgorithm::Argon2i);
    }

    #[test]
    fn test_parse_algorithm_bcrypt() {
        let hash_str = "$bcrypt$somehashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert_eq!(algorithm.unwrap(), HashAlgorithm::Bcrypt);
    }

    #[test]
    fn test_parse_algorithm_scrypt() {
        let hash_str = "$scrypt$somehashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert_eq!(algorithm.unwrap(), HashAlgorithm::Scrypt);
    }

    #[test]
    fn test_parse_algorithm_unsupported() {
        let hash_str = "$unsupported$somehashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert!(algorithm.is_err());
        assert_eq!(algorithm.err().unwrap(), "Unsupported hash algorithm: unsupported");
    }

    #[test]
    fn test_parse_algorithm_invalid() {
        let hash_str = "invalidhashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert!(algorithm.is_err());
        assert_eq!(algorithm.err().unwrap(), "Invalid hash string");
    }

}
