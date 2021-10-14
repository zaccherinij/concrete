use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextDecryptionEngine, GlweCiphertextZeroEncryptionEngine,
    GlweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the glwe decryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,          // The benckmarked engine, implementing the decryption trait
    SecretKey,       // The secret key type
    Ciphertext,      // The glwe ciphertext type
    PlaintextVector, // The plaintext vector type
    UtilEngine,      // The util engine used to generate all operator inputs
>(
    c: &mut Criterion,
) where
    Engine: GlweCiphertextDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>,
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    Ciphertext: GlweCiphertextEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: GlweCiphertextZeroEncryptionEngine<SecretKey, Ciphertext>
        + GlweSecretKeyGenerationEngine<SecretKey>,
{
    let mut group = c.benchmark_group(benchmark_name!(impl GlweCiphertextDecryptionEngine<
            SecretKey, 
            Ciphertext,
            PlaintextVector
            > for Engine));

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (glwe_dimension, poly_size) = param.to_owned();
                let secret_key = util_engine
                    .generate_glwe_secret_key(glwe_dimension, poly_size)
                    .unwrap();
                let glwe_ciphertext = util_engine
                    .zero_encrypt_glwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        black_box(engine.decrypt_glwe_ciphertext_unchecked(
                            black_box(&secret_key),
                            black_box(&glwe_ciphertext),
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
const PARAMETERS: [(GlweDimension, PolynomialSize); 5] = [
    (GlweDimension(1), PolynomialSize(256)),
    (GlweDimension(1), PolynomialSize(512)),
    (GlweDimension(1), PolynomialSize(1024)),
    (GlweDimension(1), PolynomialSize(2048)),
    (GlweDimension(1), PolynomialSize(4096)),
];
