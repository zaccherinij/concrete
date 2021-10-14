use crate::utils::benchmark_name;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::LweSecretKeyGenerationEngine;

use concrete_core::specification::entities::LweSecretKeyEntity;
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe secret key generation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,    // The benchmarked engine implementing the key generation trait.
    SecretKey, // The lwe secret key tye
>(
    c: &mut Criterion,
) where
    Engine: LweSecretKeyGenerationEngine<SecretKey>,
    SecretKey: LweSecretKeyEntity,
{
    let mut group =
        c.benchmark_group(benchmark_name!(impl LweSecretKeyGenerationEngine<SecretKey> for Engine));

    let mut engine = Engine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let lwe_dim = param.to_owned();
                b.iter(|| {
                    unsafe { black_box(engine.generate_lwe_secret_key_unchecked(lwe_dim)) };
                });
            },
        );
    }
    group.finish();
}

/// The parameters the benchmark is executed against.
const PARAMETERS: [LweDimension; 6] = [
    (LweDimension(100)),
    (LweDimension(300)),
    (LweDimension(600)),
    (LweDimension(1000)),
    (LweDimension(3000)),
    (LweDimension(6000)),
];
