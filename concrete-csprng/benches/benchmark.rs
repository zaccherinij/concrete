use concrete_csprng::{
    seeders, BytesPerChild, ChildCount, ForkableGenerator, Hardware, RandomBytesGenerator,
    RandomGenerator, Software,
};
use criterion::{criterion_group, criterion_main, Criterion};

const N_GEN: usize = 1_000_000;

fn unbounded_benchmark(
    c: &mut Criterion,
    mut generator: impl RandomBytesGenerator,
    id: &'static str,
) {
    c.bench_function(id, |b| {
        b.iter(|| {
            (0..N_GEN).for_each(|_| {
                generator.generate_next();
            })
        })
    });
}

fn bounded_benchmark(
    c: &mut Criterion,
    mut generator: impl RandomBytesGenerator + ForkableGenerator,
    id: &'static str,
) {
    let mut generator = generator
        .try_fork(ChildCount(1), BytesPerChild(N_GEN * 10_000))
        .unwrap()
        .next()
        .unwrap();
    c.bench_function(id, |b| {
        b.iter(|| {
            (0..N_GEN).for_each(|_| {
                generator.generate_next();
            })
        })
    });
}

fn software_bounded_bench(c: &mut Criterion) {
    let aes_key = seeders::default().and_then(|mut s| s.seed_key()).unwrap();
    let generator = RandomGenerator::<Software>::try_new(aes_key).unwrap();
    bounded_benchmark(c, generator, "software bounded")
}

fn software_unbounded_bench(c: &mut Criterion) {
    let aes_key = seeders::default().and_then(|mut s| s.seed_key()).unwrap();
    let generator = RandomGenerator::<Software>::try_new(aes_key).unwrap();
    unbounded_benchmark(c, generator, "software unbounded")
}

fn hardware_bounded_bench(c: &mut Criterion) {
    let aes_key = seeders::default().and_then(|mut s| s.seed_key()).unwrap();
    if let Ok(generator) = RandomGenerator::<Hardware>::try_new(aes_key) {
        bounded_benchmark(c, generator, "hardware bounded")
    } else {
        eprintln!("Hardware not supported, bounded bench skipped");
    }
}

fn hardware_unbounded_bench(c: &mut Criterion) {
    let aes_key = seeders::default().and_then(|mut s| s.seed_key()).unwrap();
    if let Ok(generator) = RandomGenerator::<Hardware>::try_new(aes_key) {
        unbounded_benchmark(c, generator, "hardware unbounded")
    } else {
        eprintln!("Hardware not supported, bounded bench skipped");
    }
}

criterion_group!(
    software_benches,
    software_unbounded_bench,
    software_bounded_bench
);

criterion_group!(
    hardware_benches,
    hardware_unbounded_bench,
    hardware_bounded_bench
);

criterion_main!(software_benches, hardware_benches);
