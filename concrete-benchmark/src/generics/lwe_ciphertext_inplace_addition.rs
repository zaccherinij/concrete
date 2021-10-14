use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    LweCiphertextInplaceAdditionEngine, LweCiphertextZeroEncryptionEngine,
    LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe addition operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine, implementing the addition trait.
    InputCiphertext,  // The lwe ciphertext type.
    OutputCiphertext, // The output ciphertext type.
    UtilEngine,       // The util engine used to generate all operator inputs.
    UtilSecretKey,    // The util secret key used to generate the ciphertexts.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextInplaceAdditionEngine<InputCiphertext, OutputCiphertext>,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    UtilEngine: LweSecretKeyGenerationEngine<UtilSecretKey>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, InputCiphertext>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, OutputCiphertext>,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweCiphertextInplaceAdditionEngine<
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
                let lwe_dim = param.to_owned();
                let secret_key = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                let mut output = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                let input_1 = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                let input_2 = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                b.iter(|| {
                    unsafe {
                        engine.inplace_add_lwe_ciphertext_unchecked(
                            black_box(&mut output),
                            black_box(&input_1),
                            black_box(&input_2),
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
const PARAMETERS: [LweDimension; 6] = [
    (LweDimension(100)),
    (LweDimension(300)),
    (LweDimension(600)),
    (LweDimension(1000)),
    (LweDimension(3000)),
    (LweDimension(6000)),
];
