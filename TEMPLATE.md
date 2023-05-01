<!-- markdownlint-disable MD041 -->
## Quantum-Resistant Cryptographic Hash Library for Password Hashing and Verification in Rust 🦀

[![Made With Rust][made-with-rust]][6] [![Crates.io][crates-badge]][8] [![Lib.rs][libs-badge]][10] [![Docs.rs][docs-badge]][9] [![License][license-badge]][2] [![Codecov][codecov-badge]][11]

![divider][divider]

## Welcome to HSH 👋

![HSH Banner][banner]

<!-- markdownlint-disable MD033 -->
<center>

**[Website][0]
• [Documentation][9]
• [Report Bug][3]
• [Request Feature][3]
• [Contributing Guidelines][4]**

</center>

<!-- markdownlint-enable MD033 -->

## Overview 📖

The Hash (HSH) library is a cryptographic hash library for password hashing and verification in Rust, based on the `argon2rs` crate.

This library is designed to provide robust security for passwords, utilizing the latest advancements in quantum-resistant cryptography.

It is based on the `argon2rs` crate. The library implements a struct named `Hash` that provides various methods for password hash generation, retrieval, and verification.

## Features ✨

### Hash Struct

The `Hash` struct has three fields:

- `password`: A string that stores the plaintext password.
- `hash`: A vector of bytes that stores the hashed password.
- `salt`: A vector of bytes that stores the salt used for password
  hashing.

### Hash Methods

The `Hash` structure provides the following methods for password hashing
and verification:

- `generate_hash`: A static method that generates a hash from a plaintext password and salt.
- `hash`: A method that returns the hash as a slice of bytes.
- `salt`: A method that returns the salt as a slice of bytes.
- `hash_length`: A method that returns the length of the hash.
- `new`: A constructor method that creates a new `Hash` struct instance with the given plaintext password and salt.
- `password`: A method that returns the password as a string.
- `password_length`: A method that returns the length of the password.
- `set_password`: A method that sets a new password and generates a new hash.
- `set_hash`: A method that sets a new hash.
- `set_salt`: A method that sets a new salt.
- `from_hash`: A method that creates a `Hash` struct instance from a given hash.
- `verify`: A method that verifies a plaintext password against the stored hash.
- `to_string_representation`: A method that returns the hash as a string.

### Traits

The `Hash` struct also implements the following traits:

- `FromStr`: Allows the `Hash` struct to be converted from a string.
- `std::fmt::Display`: Allows the `Hash` struct to be printed as a string.

### Macros

The library also provides several macros for common operations on the `Hash` struct:

- `password_length`: Returns the length of the password for a given `Hash` struct instance.
- `set_hash`: Sets a new hash value for a given `Hash` struct instance.
- `set_password`: Sets a new password and salt value for a given `Hash` struct instance.
- `set_salt`: Sets a new salt value for a given `Hash` struct instance.
- `generate_hash`: Generates a new hash for a given password and salt.
- `verify_password`: Verifies if the password matches the hash of a given `Hash` struct instance.
- `new_hash`: Creates a new instance of the `Hash` struct with the given password and salt.
- `display_hash`: Prints the hash of a given `Hash` struct instance to the console.
- `to_string`: Converts a given `Hash` struct instance to a string.

### Security and Performance

It is important to note that the library uses the `argon2rs` crate for password hashing, which is a secure and quantum-resistant password hashing library.

## Changelog 📚

-

[0]: https://minifunctions.com
[2]: http://opensource.org/licenses/MIT
[3]: https://github.com/sebastienrousseau/hsh/issues
[4]: https://raw.githubusercontent.com/sebastienrousseau/hsh/main/CONTRIBUTING.md
[6]: https://github.com/sebastienrousseau/hsh/graphs/contributors
[8]: https://crates.io/crates/hsh
[9]: https://docs.rs/hsh
[10]: https://lib.rs/crates/hsh
[11]: https://codecov.io/github/sebastienrousseau/hsh

[banner]: https://raw.githubusercontent.com/sebastienrousseau/vault/main/assets/hsh/banners/banner-hsh-1597x377.svg "HSH Banner"
[codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/hsh?style=for-the-badge&token=X3ZP0K1SGI 'Codecov'
[crates-badge]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge 'Crates.io'
[divider]: https://kura.pro/common/images/elements/divider.svg "divider"
[docs-badge]: https://img.shields.io/docsrs/hsh.svg?style=for-the-badge 'Docs.rs'
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.3-orange.svg?style=for-the-badge 'Lib.rs'
[license-badge]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge 'License'
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
