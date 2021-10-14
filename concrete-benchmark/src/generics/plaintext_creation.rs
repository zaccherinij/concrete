use crate::utils::{benchmark_name, RawNumeric};
use concrete_core::specification::engines::PlaintextCreationEngine;
use concrete_core::specification::entities::PlaintextEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the plaintext creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<Engine, Raw, Plaintext>(c: &mut Criterion)
where
    Engine: PlaintextCreationEngine<Raw, Plaintext>,
    Raw: RawNumeric,
    Plaintext: PlaintextEntity,
{
    let mut group =
        c.benchmark_group(benchmark_name!(impl PlaintextCreationEngine<Raw, Plaintext> for Engine));

    let mut engine = Engine::new().unwrap();

    group.bench_with_input(
        BenchmarkId::from_parameter("()".to_string()),
        &(),
        |b, _param| {
            b.iter(|| {
                unsafe { black_box(engine.create_plaintext_unchecked(black_box(&Raw::any()))) };
            });
        },
    );
    group.finish();
}
