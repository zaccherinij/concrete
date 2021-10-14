use crate::utils::{benchmark_name, RawNumeric};
use concrete_core::specification::engines::CleartextCreationEngine;
use concrete_core::specification::entities::CleartextEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the cleartext creation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,    // The benckmarked engine, implementing the cleartext creation trait.
    Raw,       // The raw numeric type used to create the cleartext.
    Cleartext, // The cleartext type
>(
    c: &mut Criterion,
) where
    Engine: CleartextCreationEngine<Raw, Cleartext>,
    Raw: RawNumeric,
    Cleartext: CleartextEntity,
{
    let mut group =
        c.benchmark_group(benchmark_name!(impl CleartextCreationEngine<Raw, Cleartext> for Engine));

    let mut engine = Engine::new().unwrap();

    group.bench_with_input(
        BenchmarkId::from_parameter("()".to_string()),
        &(),
        |b, _param| {
            b.iter(|| {
                unsafe { black_box(engine.create_cleartext_unchecked(black_box(&Raw::any()))) };
            });
        },
    );
    group.finish();
}
