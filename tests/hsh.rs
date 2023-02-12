#[cfg(test)]
mod tests {

    extern crate hsh;
    use std::str::FromStr;

    use hsh::to_string;

    use self::hsh::{
        generate_hash, new_hash, set_hash, set_password, set_salt, verify_password, Hash,
    };

    #[test]
    fn test_macro_generate_hash() {
        let hash = generate_hash!("password", "salt12345");
        assert!(!hash.is_empty());
    }

    #[test]
    fn test_macro_set_hash() {
        let mut hash = Hash::new("password", "salt12345");
        set_hash!(hash, b"new_hash");
        assert_eq!(hash.hash(), b"new_hash");
    }

    #[test]
    fn test_macro_set_password() {
        let mut hash = Hash::new("password", "salt12345");
        set_password!(hash, "new_password", "new_salt12345");
        assert_eq!(hash.password(), "new_password");
        assert_eq!(hash.salt().to_vec(), "salt12345".as_bytes().to_vec());
    }

    #[test]
    fn test_macro_set_salt() {
        let mut hash = Hash::new("password", "salt12345");
        set_salt!(hash, b"new_salt");
        assert_eq!(hash.salt().to_vec(), b"new_salt".to_vec());
    }

    #[test]
    fn test_macro_verify_password() {
        let hash = Hash::new("password", "salt12345");
        assert!(verify_password!(hash, "password"));
    }

    #[test]
    fn test_macro_new_hash() {
        let hash = new_hash!("password", "salt12345");
        assert_eq!(hash.password(), "password");
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
