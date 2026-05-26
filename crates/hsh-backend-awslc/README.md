<!-- SPDX-License-Identifier: Apache-2.0 OR MIT -->

# `hsh-backend-awslc`

FIPS 140-3 routing layer for the [`hsh`](https://crates.io/crates/hsh)
password-hashing crate. Wraps [`aws-lc-rs`](https://docs.rs/aws-lc-rs)
with `features = ["fips"]` so that PBKDF2-HMAC-SHA-256 / SHA-512
derivations run inside the
[AWS-LC FIPS 3.0 module (CMVP Cert #4759)](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4759).

This crate is **not the primary entry point** for `hsh` users — depend
on `hsh` with the `fips` feature flag and the routing happens
automatically.

## Why a separate crate?

Pulling `aws-lc-rs = { features = ["fips"] }` builds the AWS-LC FIPS
sub-module, which has heavyweight build-host prerequisites
(Go ≥ 1.21, CMake ≥ 3.18, recent clang). Carrying that into the
default `cargo build --workspace` set would block every contributor
without a FIPS-capable toolchain — so the dependency lives in its own
crate that `hsh` only pulls in via `--features fips`.

## Scope

This crate exposes exactly one derive function:

```rust
hsh_backend_awslc::pbkdf2_derive(
    password, salt, Prf::Sha256, iterations, dk_len,
) -> Result<Vec<u8>, DeriveError>
```

Argon2id, bcrypt, and scrypt are deliberately **not** re-exported.
None of them has a CMVP-validated implementation anywhere — see
[`doc/adr/0004-fips-strategy.md`](../../doc/adr/0004-fips-strategy.md).

## Build requirements

The first build of this crate (or any reverse dependency) will
compile AWS-LC's FIPS sub-module from source. Required on the build
host:

| Tool   | Version  | macOS                           | Linux                                  |
|--------|----------|---------------------------------|----------------------------------------|
| Go     | ≥ 1.21   | `brew install go`               | distro package or `mise use go@1.21`   |
| CMake  | ≥ 3.18   | `brew install cmake`            | distro package                         |
| clang  | ≥ 14     | Xcode Command Line Tools        | distro `clang` / `clang-14`            |

Builds typically take 2–4 minutes the first time, then are cached.

## License

Dual-licensed under [MIT](../../LICENSE-MIT) OR
[Apache-2.0](../../LICENSE-APACHE) at your option.
