<!-- SPDX-FileCopyrightText: 2023-2026 Hash (HSH) library contributors -->
<!-- SPDX-License-Identifier: MIT OR Apache-2.0 -->

# hsh-kms internals

Contributor-facing map of the `hsh-kms` crate — the `Pepper` trait
and pluggable KMS / HSM backends.

## Module map

```text
crates/hsh-kms/src/
├── lib.rs              # Pepper trait + LocalPepper + KeyVersion
├── error.rs            # PepperError enum
├── aws.rs              # AWS KMS backend (feature `aws-kms`; stub)
├── gcp.rs              # GCP Cloud KMS backend (feature `gcp-kms`; stub)
├── azure.rs            # Azure Key Vault backend (feature `azure-key-vault`; stub)
└── vault.rs            # HashiCorp Vault Transit backend (feature `hashicorp-vault`; stub)
```

## The `Pepper` trait

```rust
pub trait Pepper: fmt::Debug + Send + Sync {
    fn apply(
        &self,
        version: KeyVersion,
        password: &[u8],
    ) -> Result<[u8; 32], PepperError>;

    fn current(&self) -> KeyVersion;
}
```

Three requirements:

1. **`apply` computes HMAC-SHA-256.** All providers must produce the
   same 32-byte tag for the same `(key, password)` pair. Anything
   else breaks rotation — a hash minted under v1 must verify under
   v1 when v2 is current.

2. **`current` is monotonic.** New hashes are minted under
   `current()`; older versions remain queryable so legacy hashes
   still verify. Returning a current version that isn't in the
   keyset is undefined behaviour (the in-memory `LocalPepper`
   builder rejects this; provider implementations should mirror).

3. **`Send + Sync + Debug`** so a `Policy` carrying an
   `Arc<dyn Pepper>` can cross thread boundaries and round-trip
   through `tracing` / `log` without leaking key bytes (the `Debug`
   impl must redact).

## `LocalPepper` wire format

```text
LocalPepper {
    keys: BTreeMap<KeyVersion, Vec<u8>>,   // ZeroizeOnDrop
    current: KeyVersion,
}
```

- `BTreeMap` (not `HashMap`) so iteration order is deterministic for
  the `versions()` accessor.
- Every key buffer is `ZeroizeOnDrop` so process-memory dumps don't
  contain the key material after the `LocalPepper` is dropped.
- The builder enforces `key.len() >= 16` — HMAC-SHA-256 keys
  shorter than the hash output are weaker than the cipher itself.

## The `hsh-pepper:<keyver>:<inner>` wrapper format

Lives in `hsh::api`, not here — but the wire format is owned by
this crate's contract. See [`../../hsh/doc/internals.md`](../../hsh/doc/internals.md#the-peppered-hash-wire-format)
for the details.

The split is intentional: `hsh-kms` knows how to *compute* the
HMAC tag; `hsh` knows how to *encode* the resulting wrapped string.

## Adding a new provider

1. Create `src/<provider>.rs` with a `<Provider>Pepper` struct that
   implements `Pepper`.
2. Gate the module + struct behind a new feature flag in
   `Cargo.toml`:
   ```toml
   <provider>-kms = ["dep:<sdk-crate>"]
   ```
3. Implement `apply` by calling into the provider's HMAC primitive
   (most KMS APIs expose `Sign(HMAC, key)` directly).
4. Implement `current` by tracking the configured "current" key
   alias / version locally — never query the KMS on every call.
5. Cache the *result* of `apply` only if the provider's API rate-
   limits HMAC calls; otherwise pass through. Caching introduces
   timing side-channel risk if not done carefully.
6. Add integration tests under `tests/<provider>.rs` gated on the
   feature flag.

Today all four provider modules are stubs — the trait + feature
flags are stable, the network calls land per-provider in v0.0.10+.

## Testing strategy

- `tests/coverage.rs` exercises the `LocalPepper` builder, the
  `KeyVersion` accessors, the `PepperError` Display impls, and the
  `Pepper::apply` round-trip (deterministic, distinguishes passwords,
  cross-version differs).
- `examples/local_pepper.rs` shows the smallest end-to-end use.
- `examples/rotation.rs` shows the two-version keyset pattern.
- `examples/refuse_without_pepper.rs` shows the fail-closed contract.

## Key zeroization

`LocalPepper`'s `Drop` impl explicitly zeroizes each key buffer:

```rust
impl Drop for LocalPepper {
    fn drop(&mut self) {
        for k in self.keys.values_mut() {
            k.zeroize();
        }
    }
}
```

This is belt-and-braces — `Vec<u8>` doesn't implement
`ZeroizeOnDrop` directly, so we do it explicitly on the inner
buffers when the owning `LocalPepper` drops. Provider
implementations that hold key material in process memory should
follow the same pattern.
