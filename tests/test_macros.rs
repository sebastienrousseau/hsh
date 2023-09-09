// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[cfg(test)]
mod tests {

    // Importing hsh crate and all of its macros
    extern crate hsh;
    use hsh::{generate_hash, hash_length, new_hash, Hash};
    use hsh::{
        hsh_assert, hsh_contains, hsh_in_range, hsh_join, hsh_max,
        hsh_min, hsh_parse, hsh_print, hsh_print_vec, hsh_split,
        hsh_vec, match_algo, random_string, to_str_error,
        HashAlgorithm,
    };

    #[test]
    #[should_panic(expected = "Assertion failed!")]
    fn macro_hsh_assert_fail() {
        // Test that hsh_assert! macro correctly triggers a panic when the argument is false
        hsh_assert!(false);
    }

    #[test]
    fn macro_hsh_assert() {
        // Test that hsh_assert! macro does not trigger a panic when the argument is true
        hsh_assert!(true);
    }

    #[test]
    fn macro_hsh_join() {
        // Test that hsh_join! macro correctly joins the string arguments together
        let s = hsh_join!(" ", "Hello", "world");
        assert_eq!(s, "Hello world");
    }

    #[test]
    fn macro_hsh_min() {
        // Test that hsh_min! macro correctly identifies the minimum value among the arguments
        assert_eq!(hsh_min!(10, 20, 30), 10);
    }

    #[test]
    fn macro_hsh_max() {
        // Test that hsh_max! macro correctly identifies the maximum value among the arguments
        assert_eq!(hsh_max!(10, 20, 30), 30);
    }

    #[test]
    fn macro_hsh_print() {
        // Test that hsh_print! macro correctly prints the argument
        hsh_print!("Hello, World!");
    }

    #[test]
    fn macro_hsh_print_vec() {
        // Test that hsh_print_vec! macro correctly prints the elements of the vector argument
        hsh_print_vec!(&[1, 2, 3]);
    }

    #[test]
    fn macro_hsh_split() {
        // Test that hsh_split! macro correctly splits the string argument into a vector of words
        let v = hsh_split!("Hello World");
        assert_eq!(v, vec!["Hello", "World"]);
    }

    #[test]
    fn macro_hsh_vec() {
        // Test that hsh_vec! macro correctly creates a vector from the arguments
        let v = hsh_vec!(1, 2, 3);
        assert_eq!(v, &[1, 2, 3]);
    }

    #[test]
    fn macro_hsh_contains() {
        // Test that hsh_contains! macro correctly checks if the first string contains the second
        assert!(hsh_contains!("Hello", "H"));
        assert!(!hsh_contains!("Hello", "x"));
    }


    #[test]
    fn macro_hsh_in_range() {
        let lower_bound = 0;
        let upper_bound = 100;
        let test_val1 = 10;
        let test_val2 = -10;

        assert!(hsh_in_range!(test_val1, lower_bound, upper_bound));
        assert!(!hsh_in_range!(test_val2, lower_bound, upper_bound));
    }


    #[test]
    fn macro_hsh_parse() {
        let input: Result<u64, _> = hsh_parse!("42");
        assert_eq!(input, Ok(42));
    }

    #[test]
    fn macro_to_str_error() {
        let result: Result<(), String> = Ok(());
        let error: Result<(), String> =
            Err("Error message".to_string());

        let result_str = to_str_error!(result);
        assert_eq!(result_str, Ok(()));

        let error_str = to_str_error!(error);
        assert_eq!(error_str, Err("Error message".to_string()));
    }

    #[test]
    fn macro_random_string() {
        let random = random_string!(10);
        assert_eq!(random.len(), 10);
    }

    #[test]
    fn macro_match_algo() {
        let algo_str = "bcrypt";
        let algo_result = match_algo!(algo_str);
        assert_eq!(algo_result, Ok(HashAlgorithm::Bcrypt));

        let unsupported_str = "md5";
        let unsupported_result = match_algo!(unsupported_str);
        assert_eq!(
            unsupported_result,
            Err("Unsupported hash algorithm: md5".to_string())
        );
    }

    #[test]
    fn macro_generate_hash() {
        let password = "password";
        let salt = "salt";
        let algo = "bcrypt";
        let hash_bytes = generate_hash!(password, salt, algo);

        assert!(hash_bytes.is_ok());
    }

    #[test]
    fn macro_new_hash() {
        let password = "password";
        let salt = "salt";
        let algo = "bcrypt";
        let hash = new_hash!(password, salt, algo);

        assert!(hash.is_ok());
    }

    #[test]
    fn macro_hash_length() {
        let password = "password";
        let salt = "salt";
        let algo = "bcrypt";

        let hash = new_hash!(password, salt, algo);
        assert!(hash.is_ok());
        let hash = hash.unwrap();

        let password_length = hash_length!(hash);
        assert_eq!(password_length, 60);
    }
}
