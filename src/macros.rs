//! # Macros for the `hsh` crate.
//!
//! This module contains macros that simplify working with Hash structs.
//!
//! The macros included in this module allow for quick and easy access
//! to common functionality provided by the Hash struct, such as
//! generating and verifying hashes, setting new password and salt
//! values, and printing a hash to the console.
//!
//! These macros can greatly simplify code that uses the Hash struct,
//! making it easier to read and maintain.
//!
//! ## Macros
//!
//! The library also provides several macros for common operations on the `Hash` struct:
//!
//! - `display_hash`: Prints the hash of a given `Hash` struct instance to the console.
//! - `generate_hash`: Generates a new hash for a given password and salt.
//! - `new_hash`: Creates a new instance of the `Hash` struct with the given password and salt.
//! - `password_length`: Returns the length of the password for a given `Hash` struct instance.
//! - `set_hash`: Sets a new hash value for a given `Hash` struct instance.
//! - `set_password`: Sets a new password and salt value for a given `Hash` struct instance.
//! - `set_salt`: Sets a new salt value for a given `Hash` struct instance.
//! - `to_string`: Converts a given `Hash` struct instance to a string.
//! - `verify_password`: Verifies a given password against a given `Hash` struct instance.
//!

/// This macro prints the hash of a given `Hash` struct instance to the
/// console.
#[macro_export]
macro_rules! display_hash {
    ($hash:expr) => {
        println!("{}", $hash)
    };
}

/// This macro generates a new hash for a given password, salt, and algorithm.
#[macro_export]
macro_rules! generate_hash {
    ($password:expr, $salt:expr, $algo:expr) => {
        Hash::generate_hash($password, $salt, $algo)
    };
}

/// This macro creates a new instance of the `Hash` struct with the
/// given password, salt, and algorithm.
#[macro_export]
macro_rules! new_hash {
    ($password:expr, $salt:expr, $algo:expr) => {
        Hash::new($password, $salt, $algo)
    };
}

/// This macro returns the length of the password for a given `Hash`
/// struct instance.
#[macro_export]
macro_rules! password_length {
    ($hash:expr) => {
        $hash.password_length()
    };
}

/// This macro sets a new hash value for a given `Hash` struct instance.
#[macro_export]
macro_rules! set_hash {
    ($hash:expr, $new_hash:expr) => {
        $hash.set_hash($new_hash)
    };
}

/// This macro sets a new password, salt, and algorithm value for a
/// given `Hash` struct instance.
#[macro_export]
macro_rules! set_password {
    ($hash:expr, $new_password:expr, $salt:expr, $algo:expr) => {
        $hash.set_password($new_password, $salt, $algo)
    };
}

/// This macro sets a new salt value for a given `Hash` struct instance.
#[macro_export]
macro_rules! set_salt {
    ($hash:expr, $new_salt:expr) => {
        $hash.set_salt($new_salt)
    };
}

/// This macro converts a given `Hash` struct instance to a string.
#[macro_export]
macro_rules! to_string {
    ($hash:expr) => {
        $hash.to_string_representation()
    };
}

/// This macro verifies a given password against a given `Hash` struct instance.
#[macro_export]
macro_rules! verify_password {
    ($password:expr, $hash:expr) => {
        $hash.verify_password($password)
    };
}
