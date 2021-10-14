use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    LweCiphertextDecryptionEngine, LweCiphertextZeroEncryptionEngine, LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe decryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,     // The benchmarked engine, implementing the decryption trait.
    SecretKey,  // The lwe secret key type.
    Ciphertext, // The lwe ciphertext type.
    Plaintext,  // The plaintext type
    UtilEngine, // The util engine used to generate all operator inputs.
    UtilRaw,    // A raw numeric type used to generate the plaintext.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextDecryptionEngine<SecretKey, Ciphertext, Plaintext>,
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity<Representation = SecretKey::Representation>,
    Ciphertext: LweCiphertextEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: LweCiphertextZeroEncryptionEngine<SecretKey, Ciphertext>
        + LweSecretKeyGenerationEngine<SecretKey>,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextDecryptionEngine<SecretKey, Ciphertext, Plaintext> for Engine),
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
                let ciphertext = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                b.iter(|| {
                    unsafe {
                        black_box(engine.decrypt_lwe_ciphertext_unchecked(
                            black_box(&secret_key),
                            black_box(&ciphertext),
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
const PARAMETERS: [LweDimension; 6] = [
    (LweDimension(100)),
    (LweDimension(300)),
    (LweDimension(600)),
    (LweDimension(1000)),
    (LweDimension(3000)),
    (LweDimension(6000)),
];
