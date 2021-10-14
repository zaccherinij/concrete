use crate::utils::benchmark_name;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::specification::engines::GlweSecretKeyGenerationEngine;

use concrete_core::specification::entities::GlweSecretKeyEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the glwe secret key generation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,    // The benchmarked engine, implementing the generation trait.
    SecretKey, // The glwe secret key type.
>(
    c: &mut Criterion,
) where
    Engine: GlweSecretKeyGenerationEngine<SecretKey>,
    SecretKey: GlweSecretKeyEntity,
{
    let mut group = c
        .benchmark_group(benchmark_name!(impl GlweSecretKeyGenerationEngine<SecretKey> for Engine));
    let mut engine = Engine::new().unwrap();
    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (glwe_dim, poly_size) = param.to_owned();

                b.iter(|| {
                    unsafe {
                        black_box(engine.generate_glwe_secret_key_unchecked(glwe_dim, poly_size))
                    };
                });
            },
        );
    }
    group.finish();
}

/// The parameters the benchmark is executed against.
const PARAMETERS: [(GlweDimension, PolynomialSize); 5] = [
    (GlweDimension(1), PolynomialSize(256)),
    (GlweDimension(1), PolynomialSize(512)),
    (GlweDimension(1), PolynomialSize(1024)),
    (GlweDimension(1), PolynomialSize(2048)),
    (GlweDimension(1), PolynomialSize(4096)),
];
