extern crate argonautica;
#[macro_use]
extern crate criterion;
extern crate md5;
extern crate sha2;

use criterion::{Criterion};
use sha2::Digest;

const DOCUMENT: &str = include_str!("hamlet.txt");
const SAMPLE_SIZE: usize = 100;

fn bench_crates(c: &mut Criterion) {
    let mut group = c.benchmark_group("bench_fast_but_insecure");
    // argonautica
    let mut hasher = argonautica::Hasher::fast_but_insecure();
    hasher.with_password(DOCUMENT);
    group.bench_function("argonautica", move |b| {
        b.iter(|| {
            let _ = hasher.hash().unwrap();
        })
    });

    // md5
    group.bench_function("md5", move |b| {
        b.iter(|| {
            let _ = md5::compute(DOCUMENT.as_bytes());
        });
    });

    // sha256
    group.bench_function("sha256", move |b| {
        b.iter(|| {
            let _ = sha2::Sha256::digest(DOCUMENT.as_bytes());
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(SAMPLE_SIZE);
    targets = bench_crates
}
criterion_main!(benches);
