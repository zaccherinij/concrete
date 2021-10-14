use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::specification::engines::{
    GlweSecretKeyGenerationEngine, LweBootstrapKeyGenerationEngine, LweSecretKeyGenerationEngine,
};

use concrete_core::specification::entities::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe bootstrap key generation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,        // The benchmarked engine, implementing the generation trait.
    LweSecretKey,  // The lwe secret key type.
    GlweSecretKey, // The glwe secret key type.
    BootstrapKey,  // The bootstrap key type.
    UtilEngine,    // The util engine used to generate all operator inputs.
>(
    c: &mut Criterion,
) where
    Engine: LweBootstrapKeyGenerationEngine<LweSecretKey, GlweSecretKey, BootstrapKey>,
    BootstrapKey: LweBootstrapKeyEntity,
    LweSecretKey: LweSecretKeyEntity<KeyFlavor = BootstrapKey::InputKeyFlavor>,
    GlweSecretKey: GlweSecretKeyEntity<KeyFlavor = BootstrapKey::OutputKeyFlavor>,
    UtilEngine:
        LweSecretKeyGenerationEngine<LweSecretKey> + GlweSecretKeyGenerationEngine<GlweSecretKey>,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweBootstrapKeyGenerationEngine<
            LweSecretKey, 
            GlweSecretKey, 
            BootstrapKey
            > for Engine));

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (input_lwe_dim, glwe_dim, poly_size, base_log, level) = param.to_owned();
                let lwe_sk = util_engine.generate_lwe_secret_key(input_lwe_dim).unwrap();
                let glwe_sk = util_engine
                    .generate_glwe_secret_key(glwe_dim, poly_size)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        black_box(engine.generate_lwe_bootstrap_key_unchecked(
                            &lwe_sk, &glwe_sk, base_log, level, VARIANCE,
                        ))
                    };
                });
            },
        );
    }
    group.finish();
}

/// The variance used to encrypt everything in the benchmark.
const VARIANCE: Variance = Variance(0.00000001);

/// The parameters the benchmark is executed against.
const PARAMETERS: [(
    LweDimension,
    GlweDimension,
    PolynomialSize,
    DecompositionBaseLog,
    DecompositionLevelCount,
); 5] = [
    (
        LweDimension(100),
        GlweDimension(1),
        PolynomialSize(256),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(100),
        GlweDimension(1),
        PolynomialSize(512),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(100),
        GlweDimension(1),
        PolynomialSize(1024),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(100),
        GlweDimension(1),
        PolynomialSize(2048),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(100),
        GlweDimension(1),
        PolynomialSize(4096),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
];
