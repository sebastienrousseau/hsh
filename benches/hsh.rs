extern crate argon2rs;
extern crate criterion;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

extern crate hsh;
use self::hsh::Hash;

fn generate_hash_benchmark(c: &mut Criterion) {
    c.bench_function("generate_hash", |b| {
        b.iter(|| Hash::generate_hash(black_box("password"), black_box("salt12345")))
    });
}

fn new_hash_benchmark(c: &mut Criterion) {
    c.bench_function("new_hash", |b| {
        b.iter(|| Hash::new(black_box("password"), black_box("salt12345")))
    });
}

fn set_password_benchmark(c: &mut Criterion) {
    let mut hash = Hash::new("password", "salt12345");

    c.bench_function("set_password", |b| {
        b.iter(|| {
            Hash::set_password(
                &mut hash,
                black_box("new_password"),
                black_box("new_salt12345"),
            )
        })
    });
}

fn verify_password_benchmark(c: &mut Criterion) {
    let hash = Hash::new("password", "salt12345");

    c.bench_function("verify_password", |b| {
        b.iter(|| Hash::verify(&hash, black_box("password")))
    });
}

criterion_group!(
    benches,
    generate_hash_benchmark,
    new_hash_benchmark,
    set_password_benchmark,
    verify_password_benchmark
);
criterion_main!(benches);
