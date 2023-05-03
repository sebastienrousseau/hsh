extern crate bcrypt;
use hsh::{
    generate_hash, new_hash, password_length, set_hash, set_password,
    set_salt, to_string, verify_password, Hash,
};

#[cfg(test)]
#[test]
// Tests the password_length! macro.
fn test_macro_password_length() {
    let hash = new_hash!("password", "salt12345", "argon2i");
    assert_eq!(password_length!(hash), 8);
}

#[test]
// Tests the set_hash! macro.
fn test_macro_set_hash() {
    let mut hash = new_hash!("password", "salt12345", "argon2i");
    let new_hash = vec![1, 2, 3];
    set_hash!(hash, &new_hash);
    assert_eq!(hash.hash, new_hash);
}

#[test]
// Tests the set_password! macro.
fn test_macro_set_password() {
    let mut hash = new_hash!("password", "salt12345", "argon2i");
    let salt = "salt12345";
    let new_password = "new_password";
    set_password!(hash, new_password, salt, "argon2i");
    assert_eq!(hash.password, new_password);
}

#[test]
// Tests the set_salt! macro.
fn test_macro_set_salt() {
    let mut hash = new_hash!("password", "salt12345", "argon2i");
    let new_salt = vec![1, 2, 3];
    set_salt!(hash, &new_salt);
    assert_eq!(hash.salt, new_salt);
}

#[test]
// Tests the to_string! macro.
fn test_macro_generate_hash() {
    let password = "password";
    let salt = "salt12345";
    let generated_hash = generate_hash!(password, salt, "argon2i");
    assert!(!generated_hash.is_empty());
    assert_eq!(generated_hash.len(), 32);
}

#[test]
// Tests the verify_password! macro.
fn test_macro_verify_password() {
    let password = "password";
    let salt = "salt12345";
    let mut hash = new_hash!(password, salt, "bcrypt");
    let verification = verify_password!(password, hash);
    assert_eq!(hash.password, password);
    assert!(!verification);
}

#[test]
// Tests the new_hash! macro.
fn test_macro_new_hash() {
    let password = "password";
    let salt = "salt12345";
    let hash = new_hash!(password, salt, "argon2i");
    assert_eq!(hash.password, password);
    assert_eq!(hash.salt, salt.as_bytes().to_vec());
}

#[test]
// Tests the to_string! macro.
fn test_macro_to_string() {
    let hash = new_hash!("password", "salt12345", "argon2i");
    let hash_string = to_string!(hash);
    assert_ne!(hash_string, String::new());
}

#[test]
// Tests the Hash::generate_hash() method.
fn test_generate_hash() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::generate_hash(password, salt, "argon2i");
    assert!(!hash.is_empty());
}

#[test]
// Tests the Hash::new() method.
fn test_new() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::new(password, salt, "argon2i");
    assert_eq!(hash.password(), password);
    assert_eq!(hash.password_length(), 8);
    assert_eq!(hash.salt().to_vec(), salt.as_bytes().to_vec());
    assert_eq!(hash.hash_length(), 32);
}

#[test]
// Tests the Hash::verify() method.
fn test_verify() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::new(password, salt, "argon2i");
    assert!(hash.verify(password));
    assert!(!hash.verify("invalid password"));
}

#[test]
// Tests the Hash::set_password() method.
fn test_set_password() {
    let password = "password";
    let salt = "salt12345";
    let mut hash = Hash::new(password, salt, "argon2i");
    let new_password = "new_password";
    hash.set_password(new_password, salt, "argon2i");
    assert_eq!(hash.password(), new_password);
    assert!(hash.verify(new_password));
    assert!(!hash.verify(password));
}

#[test]
// Tests the Hash::set_salt() method.
fn test_set_salt() {
    let password = "password";
    let salt = "salt12345";
    let mut hash = Hash::new(password, salt, "argon2i");
    let new_salt = "new_salt";
    hash.set_salt(new_salt.as_bytes());
    assert_eq!(hash.salt().to_vec(), new_salt.as_bytes().to_vec());
    assert!(!hash.verify(password));
}
#[test]
// Tests the Hash::from_hash() method.
fn test_from_hash() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::new(password, salt, "argon2i");
    let new_hash = Hash::from_hash(hash.hash(), "argon2i");
    assert_eq!(hash.hash(), new_hash.hash());
}
#[test]
// Tests the Hash::from_string_representation() method.
fn test_to_string_representation() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::new(password, salt, "argon2i");
    let string_representation = hash.to_string_representation();
    assert_eq!(string_representation.len(), 81);
}
#[test]
// Tests the Hash::display() method.
fn test_display_hash() {
    let password = "password";
    let salt = "salt12345";
    let hash = Hash::new(password, salt, "argon2i");
    let display = format!("{hash}");
    assert_eq!(
        display,
        format!(
            "Hash {{ password: {}, hash: {:?} }}",
            password,
            hash.hash()
        )
    );
}
