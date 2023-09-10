// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! # Macros for the `hsh` crate.
//!
//! This module contains macros that simplify working with Hash structs.
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
//! | `hsh` | Calls the parse method on the Common struct from the hsh crate. |
//! | `hsh_assert` | Asserts that a given condition is true. If the condition is false, the macro will cause the program to panic with the message "Assertion failed!". |
//! | `hsh_contains` | Checks if a given string contains a specified substring. |
//! | `hsh_in_range` | Checks if a given value is within a specified range (inclusive). |
//! | `hsh_join` | Joins multiple strings together using a specified separator. |
//! | `hsh_max` | Returns the maximum value from a set of given values. |
//! | `hsh_min` | Returns the minimum value from a set of given values. |
//! | `hsh_print` | Prints the given arguments to the console, similar to the `println!` macro. |
//! | `hsh_print_vec` | Prints the elements of a given vector to the console, each on a new line. |
//! | `hsh_split` | Splits a given string into a vector of words, dividing at each occurrence of whitespace. |
//! | `hsh_vec` | Creates a new vector containing the given elements. |
//! | `hsh_parse` | Attempts to parse a given input into a u64 value, returning a Result. |
//!
//! ## HSH Macros
//!
//! The library also provides several macros for common operations on the `Hash` struct:
//!
//! - `to_str_error`: Abstracts away the error handling for the `to_string` method.
//! - `random_string`: Generates a random string of a specified length, consisting of alphanumeric characters.
//! - `match_algo`: Matches given hash algorithm strings to their corresponding enum variants.
//! - `generate_hash`: Generates a new hash for a given password, salt, and algorithm.
//! - `new_hash`: Creates a new instance of the `Hash` struct with a given password, salt, and algorithm.
//! - `hash_length`: Returns the length of the hash for a given `Hash` struct instance.
//!

/// This macro takes any number of arguments and parses them into a Rust
/// value. The parsed value is returned wrapped in
/// `hsh::Common::parse()` function call.
///
#[macro_export]
macro_rules! hsh {
    ($($tt:tt)*) => {
        hsh::Hash::parse($($tt)*)
    };
}

/// This macro asserts that the given condition is true. If the
/// condition is false, the macro panics with the message "Assertion
/// failed!".
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_assert };
///
/// hsh_assert!(1 == 1);  // This will not panic
/// hsh_assert!(1 == 2);  // This will panic
/// ```
///
#[macro_export]
macro_rules! hsh_assert {
    ($($arg:tt)*) => {
        if !$($arg)* {
            panic!("Assertion failed!");
        }
    };
}

/// This macro checks if the given string contains the given substring.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_contains };
///
/// let contains = hsh_contains!("Hello world", "world");
/// ```
///
#[macro_export]
macro_rules! hsh_contains {
    ($s:expr, $sub:expr) => {
        $s.contains($sub)
    };
}

/// This macro checks if the given value is within the given range. The
/// range is inclusive of both endpoints.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_in_range };
///
/// let in_range = hsh_in_range!(5, 1, 10);  // `in_range` will be true
/// ```
///
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

/// This macro joins the given strings together with the given
/// separator.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_join };
///
/// let joined = hsh_join!(", ", "Hello", "world");
/// ```
///
#[macro_export]
macro_rules! hsh_join {
    ($sep:expr, $($s:expr),*) => {{
        let vec = vec![$($s.to_string()),*];
        vec.join($sep)
    }};
}

/// This macro finds the maximum value of the given values.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_max };
///
/// let max = hsh_max!(1, 2, 3);  // `max` will be 3
/// ```
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
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_min };
///
/// let min = hsh_min!(1, 2, 3);  // `min` will be 1
/// ```
///
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
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_print };
///
/// hsh_print!("Hello {}", "world");  // This will print "Hello world"
/// ```
#[macro_export]
macro_rules! hsh_print {
    ($($arg:tt)*) => {
        println!($($arg)*);
    };
}

/// This macro prints the given vector of values to the console. Each
/// value is printed on a new line.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_print_vec };
///
/// let vec = vec![1, 2, 3];
/// hsh_print_vec!(vec);  // This will print 1, 2, 3 on separate lines
/// ```
///
#[macro_export]
macro_rules! hsh_print_vec {
    ($($v:expr),*) => {
        for v in $($v),* {
            println!("{}", v);
        }
    };
}

/// This macro splits the given string into a vector of strings. The
/// string is split on whitespace characters.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_split };
///
/// let split = hsh_split!("Hello world");
/// ```
///
#[macro_export]
macro_rules! hsh_split {
    ($s:expr) => {
        $s.split_whitespace()
            .map(|w| w.to_string())
            .collect::<Vec<_>>()
    };
}

/// This macro creates a new vector with the given elements.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_vec };
///
/// let vec = hsh_vec!(1, 2, 3);  // `vec` will be [1, 2, 3]
/// ```
///
#[macro_export]
macro_rules! hsh_vec {
    ($($elem:expr),*) => {{
        let mut v = Vec::new();
        $(v.push($elem);)*
        v
    }};
}

/// This macro attempts to parse the given input into a u64 value. If
/// parsing fails, an error is returned with a message indicating the
/// failure.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ hsh_parse };
///
/// let parsed = hsh_parse!("123");  // `parsed` will be Ok(123)
/// ```
#[macro_export]
macro_rules! hsh_parse {
    ($input:expr) => {
        $input
            .parse::<u64>()
            .map_err(|e| format!("Failed to parse input: {}", e))
    };
}

/// This macro abstracts away the error handling for the `to_string`
/// method. If the method fails, an error is returned with the failure
/// message.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ to_str_error };
///
/// let result: Result<(), String> = Ok(());
/// let error: Result<(), String> =
/// Err("Error message".to_string());
///
/// let result_str = to_str_error!(result);
/// assert_eq!(result_str, Ok(()));
///
/// ```
#[macro_export]
macro_rules! to_str_error {
    ($expr:expr) => {
        $expr.map_err(|e| e.to_string())
    };
}

/// This macro generates a random string of the given length. The string
/// consists of alphanumeric characters (both upper and lower case).
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ random_string };
///
/// let random = random_string!(10);
/// ```
///
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

/// This macro matches the hash algorithm strings to their corresponding
/// enum variants.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::{ match_algo, HashAlgorithm };
///
/// let algo = match_algo!("bcrypt");
/// ```
///
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

/// This macro generates a new hash for a given password, salt, and
/// algorithm.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::models::data::Hash;
/// use hsh::{ generate_hash, HashAlgorithm };
///
/// let password = "password";
/// let salt = "salt";
/// let algo = "bcrypt";
/// let hash_bytes = generate_hash!(password, salt, algo);
///
/// assert!(hash_bytes.is_ok());
/// ```
///
#[macro_export]
macro_rules! generate_hash {
    ($password:expr, $salt:expr, $algo:expr) => {
        Hash::generate_hash($password, $salt, $algo)
    };
}

/// This macro creates a new instance of the `Hash` struct with the
/// given password, salt, and algorithm.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::models::data::Hash;
/// use hsh::{ new_hash, HashAlgorithm };
///
/// let password = "password";
/// let salt = "salt";
/// let algo = "bcrypt";
/// let hash = new_hash!(password, salt, algo);
///
/// assert!(hash.is_ok());
/// ```
#[macro_export]
macro_rules! new_hash {
    ($password:expr, $salt:expr, $algo:expr) => {
        Hash::new($password, $salt, $algo)
    };
}

/// This macro returns the length of the password for a given `Hash`
/// struct instance.
///
/// # Example
///
/// ```
/// extern crate hsh;
/// use hsh::models::data::Hash;
/// use hsh::{ hash_length };
/// use hsh::{ new_hash, HashAlgorithm };
///
/// let password = "password";
/// let salt = "salt";
/// let algo = "bcrypt";
///
/// let hash = new_hash!(password, salt, algo);
/// assert!(hash.is_ok());
/// let hash = hash.unwrap();
///
/// let password_length = hash_length!(hash);
/// assert_eq!(password_length, 60);
/// ```
///
#[macro_export]
macro_rules! hash_length {
    ($hash:expr) => {
        $hash.hash_length()
    };
}
