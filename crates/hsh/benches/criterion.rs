// Copyright © 2023-2026 Hash (HSH) library contributors. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Criterion benchmarks for the v0.0.9 enterprise surface.
//!
//! Three groups:
//!
//! 1. **`hash_owasp_2025`** — what users actually pay at OWASP-2025
//!    minimum parameters for each algorithm. These are the numbers
//!    referenced in `doc/PARAMETER-TUNING.md` (Phase 5).
//! 2. **`verify_owasp_2025`** — verification cost at the same params.
//! 3. **`fast_params`** — non-production parameters used by the
//!    proptest / fuzz / unit-test suites so CI doesn't blow its budget.
//!
//! Use `cargo bench -- --quick` for a smoke run, or
//! `cargo bench --bench benchmark` for the full criterion analysis.

#![allow(missing_docs, unused_results)]

use criterion::{
    black_box, criterion_group, criterion_main, Criterion, Throughput,
};
use hsh::algorithms::bcrypt::BcryptParams;
use hsh::algorithms::scrypt::ScryptParams;
use hsh::api;
use hsh::policy::{Policy, PrimaryAlgorithm};

const PASSWORD: &str = "correct horse battery staple";

fn fast_policy(primary: PrimaryAlgorithm) -> Policy {
    Policy {
        primary,
        argon2: argon2::Params::new(8, 1, 1, Some(32))
            .expect("fast test params"),
        bcrypt: BcryptParams::new(4),
        scrypt: ScryptParams {
            log_n: 8,
            r: 8,
            p: 1,
            dk_len: 32,
        },
        pbkdf2: hsh::algorithms::pbkdf2::Pbkdf2Params {
            prf: hsh::algorithms::pbkdf2::Prf::Sha256,
            iterations: 1,
            dk_len: 32,
        },
        backend: hsh::Backend::Native,
        #[cfg(feature = "pepper")]
        pepper: None,
    }
}

fn bench_hash_owasp_2025(c: &mut Criterion) {
    let mut group = c.benchmark_group("hash_owasp_2025");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10); // OWASP-2025 Argon2id is slow; keep sample count modest

    let argon_policy = Policy::owasp_minimum_2025();
    group.bench_function("argon2id_m19456_t2_p1", |b| {
        b.iter(|| {
            api::hash(black_box(&argon_policy), black_box(PASSWORD))
        });
    });

    let mut bcrypt_policy = argon_policy.clone();
    bcrypt_policy.primary = PrimaryAlgorithm::Bcrypt;
    group.bench_function("bcrypt_cost_10", |b| {
        b.iter(|| {
            api::hash(black_box(&bcrypt_policy), black_box(PASSWORD))
        });
    });

    let mut scrypt_policy = argon_policy;
    scrypt_policy.primary = PrimaryAlgorithm::Scrypt;
    group.bench_function("scrypt_N_2_17", |b| {
        b.iter(|| {
            api::hash(black_box(&scrypt_policy), black_box(PASSWORD))
        });
    });

    group.finish();
}

fn bench_verify_owasp_2025(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify_owasp_2025");
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);

    let argon_policy = Policy::owasp_minimum_2025();
    let argon_stored = api::hash(&argon_policy, PASSWORD).unwrap();
    group.bench_function("argon2id_m19456_t2_p1", |b| {
        b.iter(|| {
            api::verify_and_upgrade(
                black_box(&argon_policy),
                black_box(PASSWORD),
                black_box(&argon_stored),
            )
        });
    });

    let mut bcrypt_policy = argon_policy.clone();
    bcrypt_policy.primary = PrimaryAlgorithm::Bcrypt;
    let bcrypt_stored = api::hash(&bcrypt_policy, PASSWORD).unwrap();
    group.bench_function("bcrypt_cost_10", |b| {
        b.iter(|| {
            api::verify_and_upgrade(
                black_box(&bcrypt_policy),
                black_box(PASSWORD),
                black_box(&bcrypt_stored),
            )
        });
    });

    let mut scrypt_policy = argon_policy;
    scrypt_policy.primary = PrimaryAlgorithm::Scrypt;
    let scrypt_stored = api::hash(&scrypt_policy, PASSWORD).unwrap();
    group.bench_function("scrypt_N_2_17", |b| {
        b.iter(|| {
            api::verify_and_upgrade(
                black_box(&scrypt_policy),
                black_box(PASSWORD),
                black_box(&scrypt_stored),
            )
        });
    });

    group.finish();
}

fn bench_fast_params(c: &mut Criterion) {
    let mut group = c.benchmark_group("fast_params");
    group.throughput(Throughput::Elements(1));

    let argon_policy = fast_policy(PrimaryAlgorithm::Argon2id);
    group.bench_function("argon2id_m8_t1_p1", |b| {
        b.iter(|| {
            api::hash(black_box(&argon_policy), black_box(PASSWORD))
        });
    });

    let bcrypt_policy = fast_policy(PrimaryAlgorithm::Bcrypt);
    group.bench_function("bcrypt_cost_4", |b| {
        b.iter(|| {
            api::hash(black_box(&bcrypt_policy), black_box(PASSWORD))
        });
    });

    let scrypt_policy = fast_policy(PrimaryAlgorithm::Scrypt);
    group.bench_function("scrypt_N_2_8", |b| {
        b.iter(|| {
            api::hash(black_box(&scrypt_policy), black_box(PASSWORD))
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_hash_owasp_2025,
    bench_verify_owasp_2025,
    bench_fast_params
);
criterion_main!(benches);
