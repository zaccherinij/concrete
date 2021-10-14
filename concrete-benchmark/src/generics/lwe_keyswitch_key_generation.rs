use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use concrete_core::specification::engines::{
    LweKeyswitchKeyGenerationEngine, LweSecretKeyGenerationEngine,
};

use concrete_core::specification::entities::{LweKeyswitchKeyEntity, LweSecretKeyEntity};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe keyswitch key generation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,          // The benchmarked engine implementing the key generation trait
    InputSecretKey,  // The input lwe secret key type
    OutputSecretKey, // The output lwe secret key type
    KeyswitchKey,    // The keyswitch key type
    UtilEngine,      // The util engine used to generate all operator inputs
>(
    c: &mut Criterion,
) where
    Engine: LweKeyswitchKeyGenerationEngine<InputSecretKey, OutputSecretKey, KeyswitchKey>,
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: LweSecretKeyEntity<Representation = InputSecretKey::Representation>,
    KeyswitchKey: LweKeyswitchKeyEntity<
        InputKeyFlavor = InputSecretKey::KeyFlavor,
        OutputKeyFlavor = OutputSecretKey::KeyFlavor,
        Representation = InputSecretKey::Representation,
    >,
    UtilEngine: LweSecretKeyGenerationEngine<InputSecretKey>
        + LweSecretKeyGenerationEngine<OutputSecretKey>,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweKeyswitchKeyGenerationEngine<
            InputSecretKey, 
            OutputSecretKey, 
            KeyswitchKey
            > for Engine));

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (lwe_dim, base_log, level) = param.to_owned();
                let input_lwe_sk = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                let output_lwe_sk = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();

                b.iter(|| {
                    unsafe {
                        black_box(engine.generate_lwe_keyswitch_key_unchecked(
                            &input_lwe_sk,
                            &output_lwe_sk,
                            level,
                            base_log,
                            VARIANCE,
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
const PARAMETERS: [(LweDimension, DecompositionBaseLog, DecompositionLevelCount); 5] = [
    (
        LweDimension(100),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(200),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(300),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(400),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
    (
        LweDimension(500),
        DecompositionBaseLog(2),
        DecompositionLevelCount(3),
    ),
];
