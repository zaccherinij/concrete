use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::specification::engines::{
    GlweSecretKeyGenerationEngine, LweBootstrapKeyConversionEngine,
    LweBootstrapKeyGenerationEngine, LweSecretKeyGenerationEngine,
};

use concrete_core::specification::entities::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe bootstrap key conversion operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,             // The benchmarked engine, implementing the conversion trait.
    InputBootstrapKey,  // The input bootstrap key type.
    OutputBootstrapKey, // The output bootstrap key type.
    UtilEngine,         // The util engine used to generate the input bootstrap key.
    UtilLweSk,          // The lwe secret key type used to generate the input bootstrap key.
    UtilGlweSk,         // The glwe secret key type used to generate the input bootstrap key.
>(
    c: &mut Criterion,
) where
    Engine: LweBootstrapKeyConversionEngine<InputBootstrapKey, OutputBootstrapKey>,
    InputBootstrapKey: LweBootstrapKeyEntity,
    OutputBootstrapKey: LweBootstrapKeyEntity<
        InputKeyFlavor = InputBootstrapKey::InputKeyFlavor,
        OutputKeyFlavor = InputBootstrapKey::OutputKeyFlavor,
    >,
    UtilEngine: LweSecretKeyGenerationEngine<UtilLweSk>
        + GlweSecretKeyGenerationEngine<UtilGlweSk>
        + LweBootstrapKeyGenerationEngine<UtilLweSk, UtilGlweSk, InputBootstrapKey>,
    UtilLweSk: LweSecretKeyEntity<KeyFlavor = InputBootstrapKey::InputKeyFlavor>,
    UtilGlweSk: GlweSecretKeyEntity<KeyFlavor = OutputBootstrapKey::OutputKeyFlavor>,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweBootstrapKeyConversionEngine<
            InputBootstrapKey, 
            OutputBootstrapKey
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
                let bsk: InputBootstrapKey = util_engine
                    .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, base_log, level, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe { black_box(engine.convert_lwe_bootstrap_key_unchecked(&bsk)) };
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
