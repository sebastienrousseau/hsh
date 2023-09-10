<!-- markdownlint-disable MD033 MD041 -->

<img src="https://kura.pro/hsh/images/logos/hsh.svg"
alt="Hash (HSH) logo" width="261" align="right" />

<!-- markdownlint-enable MD033 MD041 -->
# Hash (HSH)

Quantum-Resistant Cryptographic Hash Library for Password Hashing and
Verification

*Part of the [Mini Functions][0] family of libraries.*

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

The `Hash (HSH)` Rust library provides an interface for implementing
secure hash and digest algorithms, specifically designed for password
encryption and verification.

The library provides a simple API that makes it easy to store and verify
hashed passwords. It enables robust security for passwords, using the
latest advancements in `Quantum-resistant cryptography`. Quantum-
resistant cryptography refers to cryptographic algorithms, usually
public-key algorithms, that are thought to be secure against an attack
by a quantum computer. As quantum computing continues to advance, this
feature of the library assures that the passwords managed through this
system remain secure even against cutting-edge computational
capabilities.

The library supports the following Password Hashing Schemes (Password
Based Key Derivation Functions):

- [**Argon2i**](<https://en.wikipedia.org/wiki/Argon2>): A cutting-edge
  and highly secure key derivation function designed to protect against
  both traditional brute-force attacks and rainbow table attacks.
  (Recommended)
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

The library is a valuable tool for developers who need to store and
verify passwords in a secure manner. It is easy to use and can be
integrated into a variety of applications.

## Features ✨

- **Compliant with multiple Password Hashing Schemes (Password Based Key Derivation Functions) such as Argon2i, Bcrypt and Scrypt.** This makes the library more versatile and can be used in a variety of applications.
- **Quantum-resistant, making it secure against future attacks using quantum computers.** This is an important feature as quantum computers become more powerful.
- **Easy to use.** The library provides a simple API that makes it easy to store and verify hashed passwords.
- **Can be integrated into a variety of applications.** The library is written in Rust, which makes it easy to integrate into any Rust project and is fast, efficient, and secure.

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

## Installation 📦

It takes just a few minutes to get up and running with `hsh`.

### Requirements

The minimum supported Rust toolchain version is currently Rust
**1.69.0** or later (stable). It is recommended that you install the
latest stable version of Rust.

### Platform support

`Hash (HSH)` is supported and tested on the following platforms:

### Tier 1 platforms 🏆

| | Operating System | Target | Description |
| --- | --- | --- | --- |
| ✅ | Linux   | aarch64-unknown-linux-gnu | 64-bit Linux systems on ARM architecture |
| ✅ | Linux   | i686-unknown-linux-gnu | 32-bit Linux (kernel 3.2+, glibc 2.17+) |
| ✅ | Linux   | x86_64-unknown-linux-gnu | 64-bit Linux (kernel 2.6.32+, glibc 2.11+) |
| ✅ | macOS   | x86_64-apple-darwin | 64-bit macOS (10.7 Lion or later) |
| ✅ | Windows | i686-pc-windows-gnu | 32-bit Windows (7 or later) |
| ✅ | Windows | i686-pc-windows-msvc | 32-bit Windows (7 or later) |
| ✅ | Windows | x86_64-pc-windows-gnu | 64-bit Windows (7 or later) |
| ✅ | Windows | x86_64-pc-windows-msvc | 64-bit Windows (7 or later) |

### Tier 2 platforms 🥈

| | Operating System | Target | Description |
| --- | --- | --- | --- |
| ✅ | Linux   | aarch64-unknown-linux-musl | 64-bit Linux systems on ARM architecture |
| ✅ | Linux   | arm-unknown-linux-gnueabi | ARMv6 Linux (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | arm-unknown-linux-gnueabihf | ARMv7 Linux, hardfloat (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | armv7-unknown-linux-gnueabihf | ARMv7 Linux, hardfloat (kernel 3.2, glibc 2.17) |
| ✅ | Linux   | mips-unknown-linux-gnu | MIPS Linux (kernel 2.6.32+, glibc 2.11+) |
| ✅ | Linux   | mips64-unknown-linux-gnuabi64 | MIPS64 Linux (kernel 2.6.32+, glibc 2.11+) |
| ✅ | Linux   | mips64el-unknown-linux-gnuabi64 | MIPS64 Linux (kernel 2.6.32+, glibc 2.11+) |
| ✅ | Linux   | mipsel-unknown-linux-gnu | MIPS Linux (kernel 2.6.32+, glibc 2.11+) |
| ✅ | macOS   | aarch64-apple-darwin | 64-bit macOS (10.7 Lion or later) |
| ✅ | Windows | aarch64-pc-windows-msvc | 64-bit Windows (7 or later) |

The [GitHub Actions][10] shows the platforms in which the
`Hash (HSH)` library tests are run.

### Documentation

> ℹ️ **Info:** Please check out our [website][0] for more information
and find our documentation on [docs.rs][9], [lib.rs][10] and
[crates.io][8].

## Usage 📖

To use `hsh` in your project, add the following to your `Cargo.toml`
file:

```toml
[dependencies]
hsh = "0.0.5"
```

Add the following to your `main.rs` file:

```rust
extern crate hsh;
use hsh::*;
```

then you can use the functions in your application code.

### Examples

`Hash (HSH)` comes with a set of examples that you can use to get
started. The examples are located in the `examples` directory of the
project. To run the examples, clone the repository and run the following
command in your terminal from the project root directory.

```shell
cargo run --example hsh
```

## Semantic Versioning Policy 🚥

For transparency into our release cycle and in striving to maintain
backward compatibility, `Hash (HSH)` follows [semantic versioning][7].

## License 📝

The project is licensed under the terms of both the MIT license and the
Apache License (Version 2.0).

- [Apache License, Version 2.0][1]
- [MIT license][2]

## Contribution 🤝

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms
or conditions.

![divider][divider]

## Acknowledgements 💙

A big thank you to all the awesome contributors of [Mini Functions][6]
for their help and support.

And a special thank you goes to the
[Rust Reddit](https://www.reddit.com/r/rust/) community for providing a
lot of useful suggestions on how to improve this project.

[0]: https://minifunctions.com/hsh
[1]: http://www.apache.org/licenses/LICENSE-2.0
[2]: http://opensource.org/licenses/MIT
[3]: https://github.com/sebastienrousseau/hsh/issues
[4]: https://raw.githubusercontent.com/sebastienrousseau/hsh/main/.github/CONTRIBUTING.md
[6]: https://github.com/sebastienrousseau/hsh/graphs/contributors
[7]: http://semver.org/
[8]: https://crates.io/crates/hsh
[9]: https://docs.rs/hsh
[10]: https://lib.rs/crates/hsh
[11]: https://codecov.io/github/sebastienrousseau/hsh

[banner]: https://kura.pro/hsh/images/titles/title-hsh.svg "Hash (HSH) Banner"
[codecov-badge]: https://img.shields.io/codecov/c/github/sebastienrousseau/cmn?style=for-the-badge&token=DMNW4DN0LO 'Codecov'
[crates-badge]: https://img.shields.io/crates/v/hsh.svg?style=for-the-badge 'Crates.io'
[divider]: https://kura.pro/common/images/elements/divider.svg "divider"
[docs-badge]: https://img.shields.io/docsrs/hsh.svg?style=for-the-badge 'Docs.rs'
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.5-orange.svg?style=for-the-badge 'Lib.rs'
[license-badge]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge 'License'
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
