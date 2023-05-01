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

Hash (HSH) is a Rust library that provides a secure and easy-to-use way
to store and verify hashed passwords. It's based on the `argon2rs` crate
and includes salt, password, and hash functions. The library is designed
to provide robust security for passwords, using the latest advancements
in quantum-resistant cryptography.

## Features ✨

### Secure password storage

Hash (HSH) provides a secure way to store and verify hashed passwords.
Passwords are hashed using the argon2i algorithm, which is considered
one of the most secure hashing algorithms available today. The library
provides a simple interface for generating and verifying hashes, making
it easy to implement secure password storage in any Rust application.

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

`hsh` requires Rust **1.67.0** or later.

### Documentation

> ℹ️ **Info:** Please check out our [website][0] for more information
and find our documentation on [docs.rs][9], [lib.rs][10] and
[crates.io][8].

## Usage 📖

To use `hsh` in your project, add the following to your `Cargo.toml`
file:

```toml
[dependencies]
hsh = "0.0.3"
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
[libs-badge]: https://img.shields.io/badge/lib.rs-v0.0.3-orange.svg?style=for-the-badge 'Lib.rs'
[license-badge]: https://img.shields.io/crates/l/hsh.svg?style=for-the-badge 'License'
[made-with-rust]: https://img.shields.io/badge/rust-f04041?style=for-the-badge&labelColor=c0282d&logo=rust 'Made With Rust'
