<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# `hsh-kms` deep-dive documentation

Long-form documentation for the `Pepper` trait, the `LocalPepper`
in-memory provider, and the four KMS / HSM backends (AWS / GCP /
Azure / Vault). The two-line rule:

- **Reference / API docs** live inline in `src/` as `///` rustdoc
  and render at <https://docs.rs/hsh-kms>.
- **Deployment guides, provider quirks, rotation runbook** live here.

For workspace-wide KMS deployment guidance — including how `hsh`
*uses* a pepper at the policy / verify layer — see
[`doc/KMS-INTEGRATION.md`](../../../doc/KMS-INTEGRATION.md).

## What's in this folder

| File | Audience | Covers |
|---|---|---|
| [`rotation.md`](./rotation.md) | Operators | Key rotation runbook: add v2, mark current, let stored hashes upgrade on verify, retire v1 after audit |
| [`internals.md`](./internals.md) | Contributors | `Pepper` trait contract, `LocalPepper` wire format, provider stub layout |
| [`errors.md`](./errors.md) | Library users + operators | `PepperError` variants with display, when emitted, recovery |

## What's NOT in this folder

| Looking for… | Read this instead |
|---|---|
| The `hsh-pepper:<keyver>:<inner>` wire format | [`crates/hsh/doc/architecture.md`](../../hsh/doc/architecture.md#the-peppered-hash-wire-format) |
| Cross-provider deployment (AWS / GCP / Azure / Vault) | [`doc/KMS-INTEGRATION.md`](../../../doc/KMS-INTEGRATION.md) |
| Per-provider implementation status (which are stubs vs real) | [`PLAN.md`](../../../PLAN.md#phase-3--pepper--kms-integration-) |
| Adding a new KMS provider | [`internals.md`](./internals.md#adding-a-new-provider) |
| Why peppering exists | [`crates/hsh/doc/cookbook.md#peppered-with-localpepper`](../../hsh/doc/cookbook.md#peppered-with-localpepper) |

## Contributor expectations

If you change the `Pepper` trait or `LocalPepper`:

- **New trait method?** Provide a default impl or this is a
  semver-major change.
- **New error variant?** Update [`errors.md`](./errors.md).
- **New KMS provider?** Add it under `src/<provider>.rs` gated on a
  new feature flag; add per-provider integration tests under
  `tests/<provider>.rs`; update [`internals.md`](./internals.md).
- **Wire-format change?** Coordinate with `hsh::api` — the wire
  format is owned by *that* crate's contract, but the HMAC tag bytes
  are owned by this trait.
