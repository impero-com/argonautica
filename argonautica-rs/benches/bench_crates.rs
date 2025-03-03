extern crate argon2;
extern crate argon2rs;
extern crate argonautica;
#[macro_use]
extern crate criterion;
extern crate rand;

use argonautica::config::{
    DEFAULT_HASH_LEN, DEFAULT_ITERATIONS, DEFAULT_MEMORY_SIZE, DEFAULT_SALT_LEN, default_lanes,
};
use criterion::{Criterion};
use rand::{TryRngCore, rngs::OsRng};

const PASSWORD: &str = "P@ssw0rd";
const SAMPLE_SIZE: usize = 10;

fn bench_crates(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_crates");
    
    // argon2rs
    let hasher = argon2rs::Argon2::new(
        /* passes */ DEFAULT_ITERATIONS,
        /* lanes */ default_lanes(),
        /* kib */ DEFAULT_MEMORY_SIZE,
        /* variant */ argon2rs::Variant::Argon2i,
    )
    .unwrap();
    group.bench_function("argon2rs", move |b| {
        b.iter(|| {
            let mut out = [0u8; DEFAULT_HASH_LEN as usize];

            let password = PASSWORD.as_bytes();

            let mut rng = OsRng;
            let mut salt = [0u8; DEFAULT_SALT_LEN as usize];
            rng.try_fill_bytes(&mut salt).unwrap();

            hasher.hash(
                /* out */ &mut out,
                /* p */ password,
                /* s */ &salt,
                /* k */ &[],
                /* x */ &[],
            );
        });
    });

    // argonautica
    let mut hasher = argonautica::Hasher::default();
    hasher
        .configure_password_clearing(false)
        .configure_variant(argonautica::config::Variant::Argon2i)
        .opt_out_of_secret_key(true);
    group.bench_function("argonautica", move |b| {
        b.iter(|| {
            let _ = hasher.with_password(PASSWORD).hash_raw().unwrap();
        })
    });

    // rust-argon2
    let config = argon2::Config {
        variant: argon2::Variant::Argon2i,
        version: argon2::Version::Version13,
        mem_cost: DEFAULT_MEMORY_SIZE,
        time_cost: DEFAULT_ITERATIONS,
        lanes: default_lanes(),
        secret: &[],
        ad: &[],
        hash_length: DEFAULT_HASH_LEN,
    };
    group.bench_function("rust-argon2", move |b| {
        b.iter(|| {
            let password = PASSWORD.as_bytes();

            let mut rng = OsRng;
            let mut salt = [0u8; DEFAULT_SALT_LEN as usize];
            rng.try_fill_bytes(&mut salt).unwrap();

            let _ = argon2::hash_raw(password, &salt[..], &config).unwrap();
        });
    });

    group.finish()
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bench_crates
}
criterion_main!(benches);
