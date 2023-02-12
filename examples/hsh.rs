extern crate hsh;
use self::hsh::{display_hash, new_hash, to_string, Hash};
use std::str::FromStr;

fn main() {
    // create a hash with a password and salt
    let mut hash = Hash::new("password", "salt1234");

    // set the password and generate a new hash
    hash.set_password("new_password", "new_salt1234");

    // verify a password against the stored hash
    let is_valid = hash.verify("new_password");
    println!("🦀 Password verification result: ✅ {is_valid}");

    // display the hash as a string
    let hash_string = format!("{hash}");
    println!("🦀 Hash string representation:   ✅ {hash_string}");

    // parse a hash from a string
    let parsed_hash = Hash::from_str(&hash_string).unwrap();
    println!("🦀 Parsed hash:                  ✅ {parsed_hash}");

    // use display macro to display the hash
    let password = "password";
    let salt = "salt12345";
    let hash = new_hash!(password, salt);
    display_hash!(hash);

    // use to_string macro to convert the hash to a string
    let hash = new_hash!("password", "salt12345");
    let hash_string = to_string!(hash);

    println!("🦀 hash_string:                 ✅ {hash_string}");
}
