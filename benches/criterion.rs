// Copyright © 2023 Hash (HSH) library. All rights reserved.
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Benchmarking the Hash (HSH) library using Criterion.rs
extern crate argon2rs;
extern crate criterion;

use criterion::{
    black_box, criterion_group, criterion_main, Criterion,
};

extern crate hsh;
use hsh::models::data::Hash;

fn generate_hash_benchmark(c: &mut Criterion) {
    c.bench_function("generate_hash", |b| {
        b.iter(|| {
            Hash::generate_hash(
                black_box("password"),
                black_box("salt12345"),
                black_box("argon2i"),
            )
        })
    });
}

fn new_hash_benchmark(c: &mut Criterion) {
    c.bench_function("new_hash", |b| {
        b.iter(|| {
            Hash::new(
                black_box("password"),
                black_box("salt12345"),
                black_box("argon2i"),
            )
        })
    });
}

fn set_password_benchmark(c: &mut Criterion) {
    let mut hash =
        Hash::new("password", "salt12345", "argon2i").unwrap(); // Unwrap the Result

    c.bench_function("set_password", |b| {
        b.iter(|| {
            Hash::set_password(
                &mut hash, // Pass the `hash` instance
                black_box("new_password"),
                black_box("new_salt12345"),
                black_box("argon2i"),
            )
            .unwrap() // Unwrap the Result
        })
    });
}

fn verify_benchmark(c: &mut Criterion) {
    let hash = Hash::new("password", "salt12345", "argon2i").unwrap(); // Unwrap the Result

    c.bench_function("verify", |b| {
        b.iter(|| hash.verify(black_box("password")).unwrap()) // Call verify on the instance
    });
}

// Run the benchmarks in a group
criterion_group!(
    // Run `benches`
    benches,
    // Run `generate_hash_benchmark`
    generate_hash_benchmark,
    // Run `new_hash_benchmark`
    new_hash_benchmark,
    // Run `set_password_benchmark`
    set_password_benchmark,
    // Run `verify_benchmark`
    verify_benchmark
);

criterion_main!(benches);
