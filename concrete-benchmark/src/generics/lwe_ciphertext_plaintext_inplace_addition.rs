use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    LweCiphertextPlaintextInplaceAdditionEngine, LweCiphertextZeroEncryptionEngine,
    LweSecretKeyGenerationEngine, PlaintextCreationEngine,
};
use concrete_core::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe plaintext addition operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine implementing the inplace plaintext addition trait.
    InputCiphertext,  // The input ciphertext type.
    Plaintext,        // The plaintext type.
    OutputCiphertext, // The output ciphertext type.
    UtilEngine,       // The utility engine used to generate ciphertexts and plaintexts.
    UtilRaw,          // The raw numeric type used to construct plaintext.
    UtilSecretKey,    // The util secret key type used to construct
>(
    c: &mut Criterion,
) where
    Engine:
        LweCiphertextPlaintextInplaceAdditionEngine<InputCiphertext, Plaintext, OutputCiphertext>,
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
    Plaintext: PlaintextEntity<Representation = InputCiphertext::Representation>,
    UtilEngine: LweSecretKeyGenerationEngine<UtilSecretKey>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, InputCiphertext>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, OutputCiphertext>
        + PlaintextCreationEngine<UtilRaw, Plaintext>,
    UtilRaw: RawNumeric,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextPlaintextInplaceAdditionEngine<
            InputCiphertext, 
            Plaintext, 
            OutputCiphertext
        > for Engine),
    );

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
                let input_2 = util_engine.create_plaintext(&UtilRaw::any()).unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_add_lwe_ciphertext_plaintext_unchecked(
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
