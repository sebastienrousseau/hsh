<!-- markdownlint-disable MD033 MD041 -->

<img src="https://kura.pro/hsh/images/logos/hsh.svg"
alt="Hash (HSH) logo" width="261" align="right" />

<!-- markdownlint-enable MD033 MD041 -->
# Hash (HSH)

Quantum-Resistant Cryptographic Hash Library for Password Hashing and
Verification in Rust 🦀

<!-- markdownlint-disable MD033 MD041 -->
<center>
<!-- markdownlint-enable MD033 MD041 -->

![Hash (HSH) Banner][banner]

[![Made With Rust][made-with-rust]][6] [![Crates.io][crates-badge]][8]
[![Lib.rs][libs-badge]][10] [![Docs.rs][docs-badge]][9]
[![License][license-badge]][2] [![Codecov][codecov-badge]][11]

• [Website][0] • [Documentation][9] • [Report Bug][3]
• [Request Feature][3] • [Contributing Guidelines][4]

<!-- markdownlint-disable MD033 MD041 -->
</center>
<!-- markdownlint-enable MD033 MD041 -->

![divider][divider]

## Overview 📖

The Hash (HSH) library is a cryptographic hash library for password
hashing and verification in Rust, designed to provide robust security
for passwords, utilizing the latest advancements in quantum-resistant
cryptography.

The library is designed to be easy to use, with a simple API that allows
for the generation, retrieval, and verification of password hashes.

It supports the following hash algorithms:

- [**Argon2i**](<https://en.wikipedia.org/wiki/Argon2>): A memory-
hard password hashing function designed to be secure against both
brute-force attacks and rainbow table attacks.
- [**Bcrypt**](<https://en.wikipedia.org/wiki/Bcrypt>): A password
hashing function designed to be secure against brute-force attacks.
It is a work-factor function, which means that it takes a certain
amount of time to compute. This makes it difficult to attack with a
brute-force algorithm.
- [**Scrypt**](<https://en.wikipedia.org/wiki/Scrypt>): A password
hashing function designed to be secure against both brute-force
attacks and rainbow table attacks. It is a memory-hard and work-
factor function, which means that it requires a lot of memory and
time to compute. This makes it very difficult to attack with a GPU
or other parallel computing device.

## Features ✨

- Generates string representations of the hash
- Includes methods for setting and verifying passwords against the hash
- Provides functions for generating hashes and salts
- Rust library for hashing and verifying passwords
- Supports external crates such as argon2rs, base64, bcrypt, scrypt, and
  vrd.
- Supports multiple hash algorithms (argon2i, bcrypt, scrypt)
- Written in Rust for speed and security

### Secure password storage

Hash (HSH) provides a secure way to store and verify hashed passwords.
Passwords are hashed using the argon2i, bcrypt, scrypt algorithms, which
are considered one of the most secure hashing algorithms available
today. The library provides a simple interface for generating and
verifying hashes, making it easy to implement secure password storage
in any Rust application.

### Easy to use

Hash (HSH) includes simple functions for generating and verifying
password hashes, and managing password and salt values. Developers can
easily integrate the library into their Rust projects and start using
it right away. The library is designed to be intuitive and easy to use,
so developers can build apps without worrying about password security.

### Flexible

Hash (HSH) allows users to customize the length of passwords and salts
used in generating hashes. This flexibility allows developers to tailor
the library to their specific needs, whether they require shorter or
longer password and salt values. The library also includes macros that
make it easy to work with the Hash structure, allowing developers to
quickly and easily set and retrieve password and salt values.

### Lightweight

Hash (HSH) is a lightweight library that can easily integrate into any
Rust project. The library has no external dependencies and is efficient.
It means that developers can add secure password storage to their
applications without having to worry about significant performance
overheads.

## Changelog 📚

-

[0]: https://minifunctions.com/hsh
[2]: http://opensource.org/licenses/MIT
[3]: https://github.com/sebastienrousseau/hsh/issues
[4]: https://raw.githubusercontent.com/sebastienrousseau/hsh/main/.github/CONTRIBUTING.md
[6]: https://github.com/sebastienrousseau/hsh/graphs/contributors
[8]: https://crates.io/crates/hsh
[9]: https://docs.rs/hsh
[10]: https://lib.rs/crates/hsh
[11]: https://codecov.io/github/sebastienrousseau/hsh

[banner]: https://kura.pro/hsh/images/titles/title-hsh.svg "Hash (HSH) Banner"
[codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/cmn?style=for-the-badge&token=DMNW4DN0LO 'Codecov'
[crates-badge]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge 'Crates.io'
[divider]: https://kura.pro/common/images/elements/divider.svg "divider"
[docs-badge]: https://img.shields.io/docsrs/hsh.svg?style=for-the-badge 'Docs.rs'
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.3-orange.svg?style=for-the-badge 'Lib.rs'
[license-badge]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge 'License'
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
