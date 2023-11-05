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
//! | `hsh` | Calls the `parse` method on the `Hash` struct from the hsh crate. |
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
/// `hsh::Hash::parse()` function call.
///
#[macro_export]
macro_rules! hsh {
    ($($token:tt)*) => {
        hsh::Hash::parse($($token)*)
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
        $value >= $min && $value <= $max
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
/// use hsh::{ match_algo, models::hash_algorithm::HashAlgorithm };
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
/// use hsh::models::hash::Hash;
/// use hsh::{generate_hash, models::hash_algorithm::{HashAlgorithm}};
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
/// use hsh::{new_hash, models::{hash::Hash, hash_algorithm::{HashAlgorithm}}};
///
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
/// use hsh::models::{hash::Hash, hash_algorithm::{HashAlgorithm}};
/// use hsh::{ hash_length, new_hash };
///
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

/// Custom logging macro for various log levels and formats.
///
/// # Parameters
///
/// * `$level`: The log level of the message.
/// * `$component`: The component where the log is coming from.
/// * `$description`: A description of the log message.
/// * `$format`: The format of the log message.
///
#[macro_export]
macro_rules! macro_log_info {
    ($level:expr, $component:expr, $description:expr, $format:expr) => {{
        use dtt::DateTime;
        use vrd::Random;
        use $crate::loggers::{Log, LogFormat, LogLevel};

        // Get the current date and time in ISO 8601 format.
        let date = DateTime::new();
        let iso = date.iso_8601;

        // Create a new random number generator
        let mut rng = Random::default();
        let session_id = rng.rand().to_string();

        let log = Log::new(
            &session_id,
            &iso,
            $level,
            $component,
            $description,
            $format,
        );
        let _ = log.log();
        log // Return the Log instance
    }};
}

/// Macros related to executing shell commands.
///
/// Executes a shell command, logs the start and completion of the operation, and handles any errors that occur.
///
/// # Parameters
///
/// * `$command`: The shell command to execute.
/// * `$package`: The name of the package the command is being run on.
/// * `$operation`: A description of the operation being performed.
/// * `$start_message`: The log message to be displayed at the start of the operation.
/// * `$complete_message`: The log message to be displayed upon successful completion of the operation.
/// * `$error_message`: The log message to be displayed in case of an error.
///
/// # Returns
///
/// Returns a `Result<(), anyhow::Error>` indicating the success or failure of the operation.
///
#[macro_export]
macro_rules! macro_execute_and_log {
    ($command:expr, $package:expr, $operation:expr, $start_message:expr, $complete_message:expr, $error_message:expr) => {{
        use anyhow::{Context, Result as AnyResult};
        use $crate::loggers::{LogFormat, LogLevel};
        use $crate::macro_log_info;

        macro_log_info!(
            LogLevel::INFO,
            $operation,
            $start_message,
            LogFormat::CLF
        );

        $command
            .run()
            .map(|_| ())
            .map_err(|err| {
                macro_log_info!(
                    LogLevel::ERROR,
                    $operation,
                    $error_message,
                    LogFormat::CLF
                );
                err
            })
            .with_context(|| {
                format!(
                    "Failed to execute '{}' for {} on package '{}'",
                    stringify!($command),
                    $operation,
                    $package
                )
            })?;

        macro_log_info!(
            LogLevel::INFO,
            $operation,
            $complete_message,
            LogFormat::CLF
        );
        Ok(())
    }};
}
