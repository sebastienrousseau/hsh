#![allow(missing_docs)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {
    use hsh::models::hash::Hash;
    use hsh::models::hash_algorithm::HashAlgorithm;
    use hsh::Error;

    #[test]
    fn test_new() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "argon2i";

        let hash = Hash::new(password, salt, algo).unwrap();

        assert_eq!(hash.algorithm(), HashAlgorithm::Argon2i);
        assert_eq!(hash.salt(), salt.as_bytes());
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
                assert!(
                    matches!(e, Error::UnsupportedAlgorithm(ref a) if a == algo)
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
        let hash_string = "$argon2i$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG";

        let hash = Hash::from_string(hash_string);

        match hash {
            Ok(hash) => {
                assert_eq!(hash.algorithm(), HashAlgorithm::Argon2i);
            }
            Err(e) => {
                panic!("Failed to parse hash string: {}", e);
            }
        }
    }

    #[test]
    fn test_from_string_invalid_hash_string() {
        let invalid_hash_string = "invalid$hash$string";

        let hash = Hash::from_string(invalid_hash_string);

        assert!(hash.is_err());
        let err = hash.unwrap_err();
        assert!(matches!(err, Error::InvalidHashString(_)));
    }

    #[test]
    fn test_generate_salt() {
        let algo = "argon2i";
        let salt = Hash::generate_salt(algo).unwrap();
        assert_eq!(salt.len(), 16);
    }

    #[test]
    fn test_generate_salt_invalid_algorithm() {
        let invalid_algo = "unsupported_algo";
        let salt = Hash::generate_salt(invalid_algo);
        assert!(salt.is_err());
        assert!(matches!(
            salt.unwrap_err(),
            Error::UnsupportedAlgorithm(ref a) if a == invalid_algo
        ));
    }

    #[test]
    fn test_generate_salt_bcrypt() {
        let algo = "bcrypt";
        let salt = Hash::generate_salt(algo).unwrap();
        assert_eq!(salt.len(), 24);
    }

    #[test]
    fn test_generate_salt_scrypt() {
        let algo = "scrypt";
        let salt = Hash::generate_salt(algo).unwrap();
        assert_eq!(salt.len(), 44);
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
        assert!(matches!(hash.unwrap_err(), Error::InvalidPassword(_)));
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

        let original_hash = Hash::new(password, salt, algo).unwrap();
        let hashed_password = original_hash.hash().to_vec();

        let from_hash = Hash::from_hash(&hashed_password, algo);
        assert!(from_hash.is_ok());
        let from_hash = from_hash.unwrap();

        assert_eq!(from_hash.algorithm(), HashAlgorithm::Scrypt);
        assert_eq!(from_hash.hash(), hashed_password.as_slice());
        assert!(from_hash.salt().is_empty());
    }

    #[test]
    fn test_from_hash_invalid_algorithm() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "unsupported_algo";

        let original_hash =
            Hash::new(password, salt, "bcrypt").unwrap();
        let hashed_password = original_hash.hash().to_vec();

        let from_hash = Hash::from_hash(&hashed_password, algo);

        assert!(from_hash.is_err());
        assert!(matches!(
            from_hash.unwrap_err(),
            Error::UnsupportedAlgorithm(ref a) if a == algo
        ));
    }

    #[test]
    fn test_hash() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let original_hash = Hash::new(password, salt, algo).unwrap();
        let hashed_password = original_hash.hash().to_vec();

        assert_eq!(original_hash.hash(), hashed_password.as_slice());
    }

    #[test]
    fn test_salt() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let original_hash = Hash::new(password, salt, algo).unwrap();
        assert_eq!(original_hash.salt(), salt.as_bytes());
    }

    #[test]
    fn test_set_hash() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let mut original_hash =
            Hash::new(password, salt, algo).unwrap();
        let new_hash = vec![1, 2, 3, 4, 5];
        original_hash.set_hash(&new_hash);

        assert_eq!(original_hash.hash(), new_hash.as_slice());
    }

    #[test]
    fn test_set_salt() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let mut original_hash =
            Hash::new(password, salt, algo).unwrap();
        let new_salt = vec![1, 2, 3, 4, 5];
        original_hash.set_salt(&new_salt);

        assert_eq!(original_hash.salt(), new_salt.as_slice());
    }

    #[test]
    fn test_to_string_representation() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let original_hash = Hash::new(password, salt, algo).unwrap();
        let string_repr = original_hash.to_string_representation();

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

        let original_hash = Hash::new(password, salt, algo).unwrap();

        assert_eq!(
            format!("{}", original_hash),
            format!("Hash {{ hash: {:?} }}", original_hash.hash())
        );
    }

    #[test]
    fn test_hash_algorithm_display() {
        let algo = HashAlgorithm::Bcrypt;
        assert_eq!(format!("{}", algo), format!("{:?}", algo));
    }

    #[test]
    fn test_hash_algorithm_from_str() {
        let algo_str = "bcrypt";
        let expected_algo = HashAlgorithm::Bcrypt;
        assert_eq!(
            algo_str.parse::<HashAlgorithm>().unwrap(),
            expected_algo
        );
    }

    #[test]
    fn test_hash_algorithm_from_str_invalid() {
        let invalid_algo_str = "invalid";
        assert!(invalid_algo_str.parse::<HashAlgorithm>().is_err());
    }

    #[test]
    fn test_parse() {
        let password = "password123";
        let salt = "somesalt";
        let algo = "bcrypt";

        let original_hash = Hash::new(password, salt, algo).unwrap();
        let hash_json = serde_json::to_string(&original_hash).unwrap();
        let parsed_hash = Hash::parse(&hash_json).unwrap();

        assert_eq!(original_hash, parsed_hash);
    }

    #[test]
    fn test_parse_invalid() {
        let invalid_json = "invalid";
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
        assert!(matches!(
            algorithm.unwrap_err(),
            Error::UnsupportedAlgorithm(ref a) if a == "unsupported"
        ));
    }

    #[test]
    fn test_parse_algorithm_invalid() {
        let hash_str = "invalidhashstring";
        let algorithm = Hash::parse_algorithm(hash_str);

        assert!(algorithm.is_err());
        assert!(matches!(
            algorithm.unwrap_err(),
            Error::InvalidHashString(_)
        ));
    }
}
