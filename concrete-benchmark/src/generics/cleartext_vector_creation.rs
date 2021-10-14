use crate::utils::{benchmark_name, RawNumeric};
use concrete_core::specification::engines::CleartextVectorCreationEngine;
use concrete_core::specification::entities::CleartextVectorEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the cleartext vector creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,          // The benckmarked engine, implementing the cleartext vector creation trait
    Raw,             // The raw numeric type used to create the cleartext vectors.
    CleartextVector, // The cleartext vector type.
>(
    c: &mut Criterion,
) where
    Engine: CleartextVectorCreationEngine<Raw, CleartextVector>,
    Raw: RawNumeric,
    CleartextVector: CleartextVectorEntity,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl CleartextVectorCreationEngine<Raw, CleartextVector> for Engine),
    );

    let mut engine = Engine::new().unwrap();

    group.bench_with_input(
        BenchmarkId::from_parameter("()".to_string()),
        &(),
        |b, _param| {
            b.iter(|| {
                unsafe {
                    black_box(
                        engine.create_cleartext_vector_unchecked(black_box(
                            Raw::any_vec(10).as_slice(),
                        )),
                    )
                };
            });
        },
    );
    group.finish();
}
