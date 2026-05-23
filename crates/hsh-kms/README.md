<p align="center">
  <img src="https://cloudcdn.pro/hsh/v1/logos/hsh.svg" alt="hsh-kms logo" width="128" />
</p>

<h1 align="center">hsh-kms</h1>

<p align="center">
  <strong>Pepper / KMS integration for <a href="../hsh/"><code>hsh</code></a> — HMAC-SHA-256 pepper with versioned key rotation and pluggable KMS backends.</strong>
</p>

<p align="center">
  <a href="https://github.com/sebastienrousseau/hsh/actions"><img src="https://img.shields.io/github/actions/workflow/status/sebastienrousseau/hsh/ci.yml?style=for-the-badge&logo=github" alt="Build" /></a>
  <a href="https://crates.io/crates/hsh-kms"><img src="https://img.shields.io/crates/v/hsh-kms.svg?style=for-the-badge&color=fc8d62&logo=rust" alt="Crates.io" /></a>
  <a href="https://docs.rs/hsh-kms"><img src="https://img.shields.io/badge/docs.rs-hsh--kms-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" alt="Docs.rs" /></a>
</p>

---

## Contents

[Install](#install) · [Concepts](#concepts) · [Quick Start](#quick-start) · [Provider matrix](#provider-matrix) · [Rotation playbook](#rotation-playbook) · [Threat model](#threat-model) · [Examples](#examples) · [Documentation](#documentation) · [License](#license)

---

## Install

```toml
[dependencies]
hsh-kms = "0.0.9"
hsh     = { version = "0.0.9", features = ["pepper"] }
```

MSRV **1.75** stable. `no_std`-friendly for `LocalPepper`; KMS providers require `std` + `tokio`.

### Provider features

| Feature              | Status   | Pulls in                                          |
| -------------------- | -------- | ------------------------------------------------- |
| `default`            | always   | `LocalPepper` + `Pepper` trait                    |
| `aws-kms`            | **stub** | (future) `aws-sdk-kms`                            |
| `gcp-kms`            | **stub** | (future) `gcloud-kms`                             |
| `azure-key-vault`    | **stub** | (future) `azure_security_keyvault`                |
| `hashicorp-vault`    | **stub** | (future) `vaultrs`                                |

Provider features today expose the stable `FetchOpts` shape and a `fetch_pepper` stub that returns `PepperError::Backend("not yet wired up")`. Real implementations land incrementally as integration-test infrastructure (localstack / cloud-mock containers) comes online.

---

## Concepts

| Concept              | What it is                                                                                                                          |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| **Pepper**           | A server-side secret applied to every password before it is hashed. Lives in a KMS / HSM, **separate from the password database**.   |
| **`Pepper` trait**   | Sync interface producing `HMAC-SHA-256(key_at(version), password)` → 32-byte tag.                                                  |
| **`KeyVersion`**     | Monotonically increasing `u32` carried alongside each peppered hash. Makes rotation non-destructive.                                |
| **`LocalPepper`**    | In-memory pepper provider. Use for tests, short-lived workloads, or pin in-process secrets at startup.                              |
| **`FetchOpts`**      | Per-provider options struct (`aws::FetchOpts`, `gcp::FetchOpts`, etc.) carrying the KMS key reference + encrypted key versions.     |

Full design rationale: [ADR-0003 — Pepper key-versioning scheme](../../doc/adr/0003-pepper-key-versioning.md).

---

## Quick Start

```rust
use hsh_kms::{KeyVersion, LocalPepper, Pepper};

# fn main() {
let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"v1-server-pepper-32-bytes-min!!!".to_vec())
    .current(KeyVersion::new(1))
    .build()
    .unwrap();

let tag = pepper.apply(KeyVersion::new(1), b"correct horse").unwrap();
assert_eq!(tag.len(), 32);
# }
```

Then attach to a [`hsh`](../hsh/) policy:

```rust,no_run
use std::sync::Arc;
use hsh::{api, Policy};
use hsh_kms::{KeyVersion, LocalPepper};

# fn main() -> Result<(), hsh::Error> {
let pepper = LocalPepper::builder()
    .add(KeyVersion::new(1), b"server-pepper-bytes-keep-secret!".to_vec())
    .current(KeyVersion::new(1))
    .build()
    .unwrap();

let policy = Policy::owasp_minimum_2025()
    .with_pepper(Arc::new(pepper));

let stored = api::hash(&policy, "user-password")?;
assert!(stored.starts_with("hsh-pepper:1:"));
# Ok(()) }
```

---

## Provider matrix

| Provider              | Module                 | `FetchOpts` shape                                        | Status   |
| --------------------- | ---------------------- | -------------------------------------------------------- | -------- |
| **In-memory**         | [`LocalPepper`]        | builder API (`add` / `current` / `build`)                | ✅ live   |
| **AWS KMS**           | [`aws`]                | `key_id`, per-version encrypted blobs, `current`         | 🚧 stub  |
| **GCP Cloud KMS**     | [`gcp`]                | `key_resource`, per-version encrypted blobs, `current`   | 🚧 stub  |
| **Azure Key Vault**   | [`azure`]              | `vault_url`, `secret_name`, per-version refs, `current`  | 🚧 stub  |
| **HashiCorp Vault**   | [`vault`]              | `address`, `mount`, `key_name`, encrypted blobs          | 🚧 stub  |

The trait shape is stable. Stubs return `PepperError::Backend("not yet wired up")`; replace with real implementations as your deployment requires.

---

## Rotation playbook

1. Generate a fresh 32-byte pepper, register it as `KeyVersion::new(N+1)` in your KMS.
2. Add it to the `LocalPepper` keyset alongside the existing versions — **do not remove old versions yet**.
3. Bump `current` to `N+1` and redeploy.
4. As users log in, `verify_and_upgrade` returns `Outcome::Valid { rehashed: Some(new_phc) }` carrying `keyver=N+1`; persist `new_phc`.
5. After a chosen window (e.g. 90 days), audit your DB for rows still on old keyvers. Force-rotate inactive users via fresh sign-in.
6. Once no rows reference an old keyver, drop it from the keyset on the next deploy.

Full deployment guide: [`doc/KMS-INTEGRATION.md`](../../doc/KMS-INTEGRATION.md).

---

## Threat model

**Defends against**

- Offline brute force after a password-DB breach (attacker doesn't have the pepper).
- Pepper-key compromise within a single rotation window (old hashes migrate transparently).

**Does NOT defend against**

- KMS compromise (the pepper is in the same trust boundary as your KMS).
- An attacker who can read both the password DB and execute code with the running app's privileges.
- Online brute force — rate-limit your login endpoint separately.

For FIPS deployments where the pepper must never leave the HSM, see [`doc/FIPS.md`](../../doc/FIPS.md).

---

## Examples

See [`crates/hsh-kms/examples/`](examples/) for runnable demos:

- `local_pepper.rs` — build a `LocalPepper` and apply it.
- `rotation.rs` — multi-version keyset + rotation simulation.
- `refuse_without_pepper.rs` — fail-closed behaviour demo.

Run with `cargo run -p hsh-kms --example local_pepper`.

---

## Documentation

| Doc                                                                          | What's in it                                                  |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------- |
| [`adr/0003-pepper-key-versioning.md`](../../doc/adr/0003-pepper-key-versioning.md) | Storage format, rotation contract, fail-closed rationale       |
| [`KMS-INTEGRATION.md`](../../doc/KMS-INTEGRATION.md)                         | AWS / GCP / Azure / Vault deployment guides                   |
| [`SECURITY.md`](../../SECURITY.md)                                           | Vulnerability reporting                                       |

---

## License

Dual-licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0) or [MIT](https://opensource.org/licenses/MIT), at your option.

<p align="right"><a href="#hsh-kms">Back to top</a></p>
