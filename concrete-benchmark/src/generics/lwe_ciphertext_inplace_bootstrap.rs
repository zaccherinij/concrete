use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
};
use concrete_core::specification::engines::{
    GlweCiphertextZeroEncryptionEngine, GlweSecretKeyGenerationEngine,
    LweBootstrapKeyGenerationEngine, LweCiphertextInplaceBootstrapEngine,
    LweCiphertextZeroEncryptionEngine, LweSecretKeyGenerationEngine,
};

use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
    LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe assigned bootstrap operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine, implementing the bootstrap trait.
    BootstrapKey,     // The bootstrap key type
    Accumulator,      // The glwe ciphertext type
    InputCiphertext,  // The input lwe ciphertext type
    OutputCiphertext, // The output lwe ciphertext type
    UtilEngine,       // The util engine used to generate all operator inputs.
    UtilInputLweSk,   // The input lwe secret key type used to generate the bootstrap key
    UtilOutputLweSk,  // The output lwe secret key type used to generate the output ciphertext
    UtilGlweSk,       // The glwe secret key type used to generate the bootstrap key
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextInplaceBootstrapEngine<
        BootstrapKey,
        Accumulator,
        InputCiphertext,
        OutputCiphertext,
    >,
    BootstrapKey: LweBootstrapKeyEntity,
    Accumulator: GlweCiphertextEntity<KeyFlavor = BootstrapKey::OutputKeyFlavor>,
    InputCiphertext: LweCiphertextEntity<
        KeyFlavor = BootstrapKey::InputKeyFlavor,
        Representation = Accumulator::Representation,
    >,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = BootstrapKey::OutputKeyFlavor,
        Representation = Accumulator::Representation,
    >,
    UtilEngine: LweSecretKeyGenerationEngine<UtilInputLweSk>
        + LweSecretKeyGenerationEngine<UtilOutputLweSk>
        + GlweSecretKeyGenerationEngine<UtilGlweSk>
        + LweBootstrapKeyGenerationEngine<UtilInputLweSk, UtilGlweSk, BootstrapKey>
        + LweCiphertextZeroEncryptionEngine<UtilInputLweSk, InputCiphertext>
        + LweCiphertextZeroEncryptionEngine<UtilOutputLweSk, OutputCiphertext>
        + GlweCiphertextZeroEncryptionEngine<UtilGlweSk, Accumulator>,
    UtilInputLweSk: LweSecretKeyEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    UtilOutputLweSk: LweSecretKeyEntity<
        KeyFlavor = OutputCiphertext::KeyFlavor,
        Representation = OutputCiphertext::Representation,
    >,
    UtilGlweSk: GlweSecretKeyEntity<
        KeyFlavor = Accumulator::KeyFlavor,
        Representation = Accumulator::Representation,
    >,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweCiphertextInplaceBootstrapEngine<
            BootstrapKey, 
            Accumulator, 
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
                let (input_lwe_dim, glwe_dim, poly_size, base_log, level) = param.to_owned();
                let output_lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
                let input_lwe_sk = util_engine.generate_lwe_secret_key(input_lwe_dim).unwrap();
                let output_lwe_sk = util_engine.generate_lwe_secret_key(output_lwe_dim).unwrap();
                let input_glwe_sk = util_engine
                    .generate_glwe_secret_key(glwe_dim, poly_size)
                    .unwrap();
                let bsk = util_engine
                    .generate_lwe_bootstrap_key(
                        &input_lwe_sk,
                        &input_glwe_sk,
                        base_log,
                        level,
                        VARIANCE,
                    )
                    .unwrap();
                let accumulator = util_engine
                    .zero_encrypt_glwe_ciphertext(&input_glwe_sk, VARIANCE)
                    .unwrap();
                let mut output_lwe = util_engine
                    .zero_encrypt_lwe_ciphertext(&output_lwe_sk, VARIANCE)
                    .unwrap();
                let input_lwe = util_engine
                    .zero_encrypt_lwe_ciphertext(&input_lwe_sk, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_bootstrap_lwe_ciphertext_unchecked(
                            black_box(&mut output_lwe),
                            black_box(&input_lwe),
                            black_box(&accumulator),
                            black_box(&bsk),
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
