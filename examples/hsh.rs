use hsh::{new_hash, Hash, HashAlgorithm};
use std::str::FromStr;

// Creating and verifying hashes
fn create_and_verify_hash() {
    // Creates a hash with a password and salt using `Hash::new`.
    let mut hash = Hash::new("password", "salt1234", "argon2i");

    // Sets a new password and salt for the hash using `Hash::set_password`.
    hash.set_password("new_password", "new_salt1234", "argon2i");

    // Verifies a password against the stored hash using `Hash::verify`.
    let is_valid = hash.verify("new_password");
    println!("🦀 Password verification result: ✅ {:>5}", is_valid);
}

// Parsing and displaying hashes
fn parse_and_display_hash() {
    // Parses a hash algorithm from a string using `HashAlgorithm::from_str`.
    let parsed_hash_algorithm =
        HashAlgorithm::from_str("argon2i").unwrap();
    println!(
        "🦀 Parsed hash algorithm:        ✅ {}",
        parsed_hash_algorithm
    );

    // Creates a new hash using the `new_hash!` macro.
    let hash = new_hash!("password", "salt12345", "argon2i");

    // Converts the hash to a string using `Hash::to_string`.
    let hash_string = hash.to_string();
    println!("🦀 Hash to a string:             ✅ {}", hash_string);

    // Parses a full hash from a string using `Hash::from_string`.
    let parsed_hash =
        Hash::from_string("$argon2i$v=19$m=4096,t=3,p=1$c2FsdDM0NTQ$XHD8WkLbGxwOyN0exjK72RTJnAdubKjFz3nqP/CjKcw");
    println!("🦀 Parsed hash:                  ✅ {:?}", parsed_hash);

    // display the hash algorithm of a hash
    let algorithm = parsed_hash.algorithm();
    println!("🦀 Hash algorithm:               ✅ {:>12}", algorithm); // add padding to align with the first line

    // get the password of a hash
    let password = parsed_hash.password();
    println!("🦀 Password:                     ✅ {:?}", password);

    // get the hash value of a hash
    let hash_value = parsed_hash.hash();
    println!("🦀 Hash value:                   ✅ {:?}", hash_value);

    // get the salt of a hash
    let salt = parsed_hash.salt();
    println!("🦀 Salt:                         ✅ {:?}", salt);

    // Get the Password string
    let password_string = parsed_hash.password();
    println!(
        "🦀 Password string:             ✅ {:?}",
        password_string
    );
}

fn main() {
    create_and_verify_hash();
    parse_and_display_hash();
}
