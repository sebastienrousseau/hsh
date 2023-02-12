#[cfg(test)]
mod tests {

    extern crate hsh;
    use std::str::FromStr;

    use hsh::to_string;

    use self::hsh::{
        generate_hash, new_hash, password_length, set_hash, set_password, set_salt,
        verify_password, Hash,
    };

    #[test]
    fn test_macro_password_length() {
        let hash = new_hash!("password", "salt12345");
        assert_eq!(password_length!(hash), 8);
    }

    #[test]
    fn test_macro_set_hash() {
        let mut hash = new_hash!("password", "salt12345");
        let new_hash = vec![1, 2, 3];
        set_hash!(hash, &new_hash);
        assert_eq!(hash.hash, new_hash);
    }

    #[test]
    fn test_macro_set_password() {
        let mut hash = new_hash!("password", "salt12345");
        let salt = "salt12345";
        let new_password = "new_password";
        set_password!(hash, new_password, salt);
        assert_eq!(hash.password, new_password);
    }

    #[test]
    fn test_macro_set_salt() {
        let mut hash = new_hash!("password", "salt12345");
        let new_salt = vec![1, 2, 3];
        set_salt!(hash, &new_salt);
        assert_eq!(hash.salt, new_salt);
    }

    #[test]
    fn test_macro_generate_hash() {
        let password = "password";
        let salt = "salt12345";
        let generated_hash = generate_hash!(password, salt);
        assert_ne!(generated_hash, vec![]);
    }

    #[test]
    fn test_macro_verify_password() {
        let hash = new_hash!("password", "salt12345");
        assert_eq!(verify_password!(hash, "password"), true);
        assert_eq!(verify_password!(hash, "incorrect_password"), false);
    }

    #[test]
    fn test_macro_new_hash() {
        let password = "password";
        let salt = "salt12345";
        let hash = new_hash!(password, salt);
        assert_eq!(hash.password, password);
        assert_eq!(hash.salt, salt.as_bytes().to_vec());
    }

    #[test]
    fn test_macro_to_string() {
        let hash = new_hash!("password", "salt12345");
        let hash_string = to_string!(hash);
        assert_ne!(hash_string, String::new());
    }

    #[test]
    fn test_generate_hash() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::generate_hash(password, salt);
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_new() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::new(password, salt);
        assert_eq!(hash.password(), password);
        assert_eq!(hash.password_length(), 8);
        assert_eq!(hash.salt().to_vec(), salt.as_bytes().to_vec());
        assert_eq!(hash.hash_length(), 32);
    }

    #[test]
    fn test_verify() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::new(password, salt);
        assert!(hash.verify(password));
        assert!(!hash.verify("invalid password"));
    }

    #[test]
    fn test_set_password() {
        let password = "password";
        let salt = "salt12345";
        let mut hash = Hash::new(password, salt);
        let new_password = "new_password";
        hash.set_password(new_password, salt);
        assert_eq!(hash.password(), new_password);
        assert!(hash.verify(new_password));
        assert!(!hash.verify(password));
    }

    #[test]
    fn test_set_salt() {
        let password = "password";
        let salt = "salt12345";
        let mut hash = Hash::new(password, salt);
        let new_salt = "new_salt";
        hash.set_salt(new_salt.as_bytes());
        assert_eq!(hash.salt().to_vec(), new_salt.as_bytes().to_vec());
        assert!(!hash.verify(password));
    }
    #[test]
    fn test_from_hash() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::new(password, salt);
        let new_hash = Hash::from_hash(hash.hash());
        assert_eq!(hash.hash(), new_hash.hash());
    }
    #[test]
    fn test_to_string_representation() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::new(password, salt);
        let string_representation = hash.to_string_representation();
        assert_eq!(string_representation.len(), 81);
    }
    #[test]
    fn test_display_hash() {
        let password = "password";
        let salt = "salt12345";
        let hash = Hash::new(password, salt);
        let display = format!("{hash}");
        assert_eq!(
            display,
            format!("Hash {{ password: {}, hash: {:?} }}", password, hash.hash())
        );
    }

    #[test]
    fn test_from_str() {
        let hash = new_hash!("password", "salt12345");
        let hash_string = to_string!(hash);
        let new_hash = Hash::from_str(&hash_string).unwrap();
        assert_eq!(hash.hash(), new_hash.hash());
    }
    #[test]
    fn test_from_str_invalid_format() {
        let invalid_hash_string = "Password length must be between 8 and 0xffffffff, inclusive";
        let new_hash = Hash::from_str(invalid_hash_string);
        assert!(new_hash.is_err());
        assert_eq!(new_hash.unwrap_err(), "Invalid string format");
    }
}
