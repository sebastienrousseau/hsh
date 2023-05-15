// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

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
//! ## Generic macros for the hsh crate.
//!
//! This crate provides the following macros:
//!
//! | Macro | Description |
//! |--------|------------|
//! | `hsh` | The main macro for the hsh crate. It takes any number of arguments and parses them into a Rust value. |
//! | `hsh_assert` | Checks if the given expression is true. |
//! | `hsh_contains` | Checks if the given string contains the given substring. |
//! | `hsh_in_range` | Checks if the given value is in the given range. |
//! | `hsh_join` | Joins a vector of strings into a single string. |
//! | `hsh_map` | Creates a new map of the given key-value pairs. |
//! | `hsh_max` | Returns the maximum of the given values. |
//! | `hsh_min` | Returns the minimum of the given values. |
//! | `hsh_parse` | Parses the given input into a Rust value. |
//! | `hsh_print_vec` | Prints a vector of elements to the console. |
//! | `hsh_print` | Prints the arguments to the console. |
//! | `hsh_split` | Splits a string into a vector of words. |
//! | `hsh_to_num` | Converts the given string to a number. |
//! | `hsh_vec` | Creates a new vector of the given elements. |
//!
//! ## HSH Macros
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
//! - `verify`: Verifies a given password against a given `Hash` struct instance.
//!
//!

/// This macro takes any number of arguments and parses them into a
/// Rust value.
#[macro_export]
macro_rules! hsh {
    ($($tt:tt)*) => {
        hsh::Common::parse($($tt)*)
    };
}

/// This macro asserts that the given condition is true. If the
/// condition is false, the macro panics with the given message.
#[macro_export]
macro_rules! hsh_assert {
    ($($arg:tt)*) => {
        if !$($arg)* {
            panic!("Assertion failed!");
        }
    };
}

/// This macro checks if the given string contains the given substring.
#[macro_export]
macro_rules! hsh_contains {
    ($s:expr, $sub:expr) => {
        $s.contains($sub)
    };
}

/// This macro checks if the given value is within the given range.
#[macro_export]
macro_rules! hsh_in_range {
    ($value:expr, $min:expr, $max:expr) => {
        if $value >= $min && $value <= $max {
            true
        } else {
            false
        }
    };
}

/// This macro joins the given strings together with the given separator.
#[macro_export]
macro_rules! hsh_join {
    ($sep:expr, $($s:expr),*) => {{
        let vec = vec![$($s.to_string()),*];
        vec.join($sep)
    }};
}

/// This macro finds the maximum value of the given values.
#[macro_export]
macro_rules! hsh_max {
    ($x:expr $(, $y:expr)*) => {{
        let mut max = $x;
        $(
            if max < $y { max = $y; }
        )*
        max
    }};
}

/// This macro finds the minimum value of the given values.
#[macro_export]
macro_rules! hsh_min {
    ($x:expr $(, $y:expr)*) => {{
        let mut min = $x;
        $(
            if min > $y { min = $y; }
        )*
        min
    }};
}

/// This macro prints the given arguments to the console.
#[macro_export]
macro_rules! hsh_print {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

/// This macro prints the given vector of values to the console.
#[macro_export]
macro_rules! hsh_print_vec {
    ($($v:expr),*) => {
        for v in $($v),* {
            println!("{}", v);
        }
    };
}

/// This macro splits the given string into a vector of strings.
#[macro_export]
macro_rules! hsh_split {
    ($s:expr) => {
        $s.split_whitespace()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
    };
}

/// This macro creates a new vector with the given elements.
#[macro_export]
macro_rules! hsh_vec {
    ($($elem:expr),*) => {{
        let mut v = Vec::new();
        $(v.push($elem);)*
        v
    }};
}

/// This macro parses the given input into a Rust value.
#[macro_export]
macro_rules! hsh_parse {
    ($input:expr) => {
        $input
            .parse::<u64>()
            .map_err(|e| format!("Failed to parse input: {}", e))
    };
}

/// This macro abstracts away the error handling for the `to_string` method.
#[macro_export]
macro_rules! to_str_error {
    ($expr:expr) => {
        $expr.map_err(|e| e.to_string())
    };
}

/// This macro generates a random string of the given length.
#[macro_export]
macro_rules! random_string {
    ($len:expr) => {{
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = vrd::Random::default();
        (0..$len as usize)
            .map(|_| {
                let index = vrd::rand_int!(rng, 0, (chars.len() - 1) as i32) as usize;
                chars
                    .chars()
                    .nth(index)
                    .unwrap()
            })
            .collect::<String>()
    }};
}

/// This macro matches the hash algorithm strings to their corresponding enum variants.
#[macro_export]
macro_rules! match_algo {
    ($algo_str:expr) => {
        match $algo_str {
            "argon2i" => Ok(HashAlgorithm::Argon2i),
            "bcrypt" => Ok(HashAlgorithm::Bcrypt),
            "scrypt" => Ok(HashAlgorithm::Scrypt),
            _ => Err(format!(
                "Unsupported hash algorithm: {}",
                $algo_str
            )),
        }
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
macro_rules! hash_length {
    ($hash:expr) => {
        $hash.hash_length()
    };
}
