use crate::utils::{benchmark_name, RawNumeric};
use concrete_core::specification::engines::PlaintextVectorCreationEngine;
use concrete_core::specification::entities::PlaintextVectorEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the plaintext vector creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<Engine, Raw, PlaintextVector>(c: &mut Criterion)
where
    Engine: PlaintextVectorCreationEngine<Raw, PlaintextVector>,
    Raw: RawNumeric,
    PlaintextVector: PlaintextVectorEntity,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl PlaintextVectorCreationEngine<Raw, PlaintextVector> for Engine),
    );

    let mut engine = Engine::new().unwrap();

    group.bench_with_input(
        BenchmarkId::from_parameter("()".to_string()),
        &(),
        |b, _param| {
            b.iter(|| {
                unsafe {
                    black_box(
                        engine.create_plaintext_vector_unchecked(black_box(
                            Raw::any_vec(10).as_slice(),
                        )),
                    )
                };
            });
        },
    );
    group.finish();
}
