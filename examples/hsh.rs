use hsh::{new_hash, Hash, HashAlgorithm};
use std::str::FromStr;

// Creating and verifying hashes
fn create_and_verify_hash() {
    // Creates a hash with a password and salt using `Hash::new`.
    let mut hash =
        Hash::new("password", "salt1234", "argon2i").unwrap();

    // Sets a new password, salt, and algorithm for the hash using `Hash::set_password`.
    hash.set_password("new_password", "new_salt1234", "argon2i")
        .unwrap();

    // Verifies a password against the stored hash using `Hash::verify`.
    let is_valid = hash.verify("new_password");
    match is_valid {
        Ok(valid) => {
            println!("🦀 Password verification result: ✅ {:>5}", valid)
        }
        Err(e) => {
            eprintln!("🦀 Error during password verification: ❌ {}", e)
        }
    }
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

    // Converts the hash to a string manually.
    let hash_string = match hash {
        Ok(hash) => format!(
            "🦀 Hash to a string:             ✅ {}",
            hash.to_string_representation()
        ),
        Err(err) => format!(
            "🦀 Hash to a string:             ❌ Error: {}",
            err
        ),
    };
    println!("{}", hash_string);
}

fn main() {
    create_and_verify_hash();
    parse_and_display_hash();
}
