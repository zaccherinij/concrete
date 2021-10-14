use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    CleartextCreationEngine, LweCiphertextCleartextInplaceMultiplicationEngine,
    LweCiphertextZeroEncryptionEngine, LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    CleartextEntity, LweCiphertextEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe cleartext multiplication operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine, implementing the multiplication trait.
    InputCiphertext,  // The input lwe ciphertext type.
    Cleartext,        // The cleartext type.
    OutputCiphertext, // The output lwe ciphertext type.
    UtilEngine,       // The util engine used to generate the lwe ciphertexts and cleartext
    UtilRaw,          // A raw numeric type used to create the cleartext.
    UtilSecretKey,    // The util lwe secret key used to generate the lwe ciphertexts
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextCleartextInplaceMultiplicationEngine<
        InputCiphertext,
        Cleartext,
        OutputCiphertext,
    >,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    Cleartext: CleartextEntity<Representation = InputCiphertext::Representation>,
    UtilEngine: LweSecretKeyGenerationEngine<UtilSecretKey>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, InputCiphertext>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, OutputCiphertext>
        + CleartextCreationEngine<UtilRaw, Cleartext>,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextCleartextInplaceMultiplicationEngine<InputCiphertext, Cleartext, OutputCiphertext> for Engine),
    );

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let secret_key = util_engine.generate_lwe_secret_key(*param).unwrap();
                let input_1 = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                let mut output = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                let input_2 = util_engine.create_cleartext(&UtilRaw::any()).unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_mul_lwe_ciphertext_cleartext_unchecked(
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
