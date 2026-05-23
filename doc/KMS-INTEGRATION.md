# KMS integration guide

`hsh` supports server-side **peppering** through the `hsh-kms` companion
crate. A pepper is a secret key held in a KMS / HSM that is mixed into
every password before it is hashed; an attacker who steals only the
password database cannot brute-force credentials offline without also
breaching the KMS.

This guide shows how to wire `hsh-kms` to each of the four supported
providers. **Today most providers ship as stubs** — the trait shape and
options structs are stable, but the network-call implementations land
incrementally as they get integration-tested against real cloud
infrastructure. The `LocalPepper` backend works end-to-end today and is
sufficient for tests and small in-process deployments.

## Concepts

- **`Pepper`** — trait that produces `HMAC-SHA-256(key, password)` for
  a given [`KeyVersion`]. See [ADR-0003](adr/0003-pepper-key-versioning.md).
- **`KeyVersion`** — monotonically increasing identifier carried
  alongside every peppered hash so rotation is non-destructive.
- **`LocalPepper`** — in-memory keyset, fetched once at startup from
  your chosen KMS.
- **`Policy::with_pepper(Arc<dyn Pepper>)`** — opts a `Policy` into
  pepper application.

## Cargo features

`hsh-kms` provider modules are gated by feature flag. Enable only what
your application needs to keep transitive dependencies minimal.

```toml
[dependencies]
hsh     = { version = "0.0.9", features = ["pepper"] }
hsh-kms = { version = "0.0.9", features = ["aws-kms"] }  # or gcp-kms / azure-key-vault / hashicorp-vault
```

## End-to-end shape (any provider)

```rust,ignore
use std::sync::Arc;
use hsh::{api, Policy};
use hsh_kms::{KeyVersion, LocalPepper};

// 1. Fetch the pepper material from your KMS (provider-specific —
//    see sections below). Returns a LocalPepper snapshot.
let pepper: LocalPepper = /* fetch from provider */;

// 2. Build a policy that carries it.
let policy = Policy::owasp_minimum_2025()
    .with_pepper(Arc::new(pepper));

// 3. Use the high-level api unchanged.
let stored = api::hash(&policy, "correct horse battery staple")?;
//                    ^^^^^^^ "hsh-pepper:1:$argon2id$v=19$..."

let outcome = api::verify_and_upgrade(&policy, password, &stored)?;
if let hsh::Outcome::Valid { rehashed: Some(new_phc) } = outcome {
    // Pepper version rotated since the original hash. Persist
    // `new_phc` so subsequent verifies are O(1).
    persist(new_phc);
}
```

## AWS KMS

> **Status (v0.0.9):** stub. The shape below is the contract the real
> implementation will provide.

### Bootstrap

1. Create a customer-managed CMK in AWS KMS (`alias/hsh-pepper`).
2. Generate a 32-byte pepper with the OS CSPRNG:
   `openssl rand -hex 32`.
3. Encrypt it with the CMK: `aws kms encrypt --key-id alias/hsh-pepper --plaintext "$(openssl rand -hex 32 | xxd -r -p | base64)"`.
4. Store the resulting `CiphertextBlob` in your app config (it is safe
   to commit — it can only be decrypted by your CMK).
5. Bump `KeyVersion` and repeat steps 2-4 each rotation.

### Application

```rust,ignore
use aws_sdk_kms::Client;
use hsh_kms::aws::{fetch_pepper, FetchOpts};

let aws_config = aws_config::load_from_env().await;
let client = Client::new(&aws_config);

let pepper = fetch_pepper(FetchOpts {
    key_id: "alias/hsh-pepper".into(),
    versions: vec![
        (KeyVersion::new(1), include_str!("../config/pepper-v1.ciphertext").into()),
        (KeyVersion::new(2), include_str!("../config/pepper-v2.ciphertext").into()),
    ],
    current: KeyVersion::new(2),
}).await?;
```

### IAM

Grant your app the `kms:Decrypt` permission only — never
`kms:CreateKey` or `kms:DeleteKey` from the running service identity.

## GCP Cloud KMS

> **Status (v0.0.9):** stub.

### Bootstrap

1. Create a symmetric key:
   `gcloud kms keys create hsh-pepper --location global --keyring hsh --purpose=encryption`.
2. Encrypt your pepper bytes:
   `gcloud kms encrypt --plaintext-file=/dev/stdin --ciphertext-file=pepper-v1.bin --key=hsh-pepper --keyring=hsh --location=global`.
3. Commit the ciphertext file.

### Application

```rust,ignore
use hsh_kms::gcp::{fetch_pepper, FetchOpts};

let pepper = fetch_pepper(FetchOpts {
    key_resource: "projects/my-project/locations/global/keyRings/hsh/cryptoKeys/hsh-pepper".into(),
    versions: vec![
        (KeyVersion::new(1), std::fs::read("config/pepper-v1.bin")?),
    ],
    current: KeyVersion::new(1),
}).await?;
```

## Azure Key Vault

> **Status (v0.0.9):** stub.

### Bootstrap

1. Create a Key Vault and a secret named `hsh-pepper`.
2. Set the secret value to a 32-byte pepper.
3. Versions of the secret are exposed via Key Vault's native versioning
   — `KeyVersion::new(n)` in `hsh-kms` maps to the secret-version index.

### Application

```rust,ignore
use hsh_kms::azure::{fetch_pepper, FetchOpts};

let pepper = fetch_pepper(FetchOpts {
    vault_url: "https://myvault.vault.azure.net/".into(),
    secret_name: "hsh-pepper".into(),
    versions: vec![/* ... */],
    current: KeyVersion::new(1),
}).await?;
```

## HashiCorp Vault Transit

> **Status (v0.0.9):** stub.

### Bootstrap

1. Enable the transit engine: `vault secrets enable transit`.
2. Create a key: `vault write -f transit/keys/hsh-pepper`.
3. Encrypt your pepper:
   `vault write transit/encrypt/hsh-pepper plaintext=$(base64 <<< 'PEPPER-BYTES')`.

### Application

```rust,ignore
use hsh_kms::vault::{fetch_pepper, FetchOpts};

let pepper = fetch_pepper(FetchOpts {
    address: "https://vault.internal:8200".into(),
    mount: "transit".into(),
    key_name: "hsh-pepper".into(),
    versions: vec![
        (KeyVersion::new(1), "vault:v1:abc...".into()),
    ],
    current: KeyVersion::new(1),
}).await?;
```

## Local development

For tests / local dev where you don't want a real KMS:

```rust
use hsh_kms::{KeyVersion, LocalPepper};

let pepper = LocalPepper::builder()
    .add(
        KeyVersion::new(1),
        std::env::var("HSH_PEPPER_V1_HEX")
            .ok()
            .and_then(|h| hex::decode(h).ok())
            .expect("set HSH_PEPPER_V1_HEX to a hex-encoded 32-byte pepper"),
    )
    .current(KeyVersion::new(1))
    .build()
    .expect("local pepper");
```

## Rotation playbook

1. Generate a fresh pepper, register it as `KeyVersion::new(N+1)` in
   your KMS.
2. Add it to the `LocalPepper` keyset alongside the existing versions
   — **do not remove old versions yet**.
3. Bump `current` to `N+1` and redeploy.
4. As users log in, `verify_and_upgrade` returns `Some(new_phc)`
   pointing at the new keyver; persist it.
5. After a chosen window (e.g. 90 days), audit your DB for rows still
   carrying old keyvers. Force-rotate inactive users by invalidating
   their sessions and triggering a fresh sign-in.
6. Once no rows reference an old keyver, you can remove it from the
   keyset on the next deploy.

## Threat model

The pepper protects against **offline brute force** after a password-DB
breach. It does **not** protect against:

- A compromise of the KMS itself.
- An attacker who can both read the password DB and execute code with
  access to the running application (the pepper is in memory).
- Online brute-force — rate-limit your login endpoint separately.

For FIPS 140-3 deployments where the pepper must never leave the HSM,
see Phase 4 (issue [#143](https://github.com/sebastienrousseau/hsh/issues/143))
— the planned `aws-lc-rs` backend can route HMAC through a validated
module, and a future `Pepper` impl can sign without exposing the key.
