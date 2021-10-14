use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};
use concrete_core::specification::engines::{
    LweCiphertextInplaceKeyswitchEngine, LweCiphertextZeroEncryptionEngine,
    LweKeyswitchKeyGenerationEngine, LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    LweCiphertextEntity, LweKeyswitchKeyEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe keyswitch operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,              // The benchmarked engine, implementing the keyswitch trait.
    KeyswitchKey,        // The keyswitch key type
    InputCiphertext,     // The input lwe ciphertext type
    OutputCiphertext,    // The output lwe ciphertext type
    UtilEngine,          // The util engine used to generate all operator inputs.
    UtilInputSecretKey,  // The input lwe secret key type used to generate the keyswitch key.
    UtilOutputSecretKey, // The output lwe secret key type used to generate the keyswitch key.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextInplaceKeyswitchEngine<KeyswitchKey, InputCiphertext, OutputCiphertext>,
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity<
        KeyFlavor = KeyswitchKey::InputKeyFlavor,
        Representation = KeyswitchKey::Representation,
    >,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = KeyswitchKey::OutputKeyFlavor,
        Representation = KeyswitchKey::Representation,
    >,
    UtilEngine: LweKeyswitchKeyGenerationEngine<UtilInputSecretKey, UtilOutputSecretKey, KeyswitchKey>
        + LweSecretKeyGenerationEngine<UtilInputSecretKey>
        + LweSecretKeyGenerationEngine<UtilOutputSecretKey>
        + LweCiphertextZeroEncryptionEngine<UtilInputSecretKey, InputCiphertext>
        + LweCiphertextZeroEncryptionEngine<UtilOutputSecretKey, OutputCiphertext>,
    UtilInputSecretKey: LweSecretKeyEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    UtilOutputSecretKey: LweSecretKeyEntity<
        KeyFlavor = OutputCiphertext::KeyFlavor,
        Representation = OutputCiphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweCiphertextInplaceKeyswitchEngine<
            KeyswitchKey, 
            InputCiphertext, 
            OutputCiphertext
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
                let ksk = util_engine
                    .generate_lwe_keyswitch_key(
                        &input_lwe_sk,
                        &output_lwe_sk,
                        level,
                        base_log,
                        VARIANCE,
                    )
                    .unwrap();
                let mut output_lwe = util_engine
                    .zero_encrypt_lwe_ciphertext(&output_lwe_sk, VARIANCE)
                    .unwrap();
                let input_lwe = util_engine
                    .zero_encrypt_lwe_ciphertext(&input_lwe_sk, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_keyswitch_lwe_ciphertext_unchecked(
                            black_box(&mut output_lwe),
                            black_box(&input_lwe),
                            black_box(&ksk),
                        )
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
