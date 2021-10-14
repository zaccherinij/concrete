use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextInplaceDecryptionEngine, GlweCiphertextZeroEncryptionEngine,
    GlweSecretKeyGenerationEngine, PlaintextVectorCreationEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace glwe decryption operation.
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
    UtilRaw,         // The raw numeric type used to generate the plaintext.
>(
    c: &mut Criterion,
) where
    Engine: GlweCiphertextInplaceDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>,
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    Ciphertext: GlweCiphertextEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: PlaintextVectorCreationEngine<UtilRaw, PlaintextVector>
        + GlweSecretKeyGenerationEngine<SecretKey>
        + GlweCiphertextZeroEncryptionEngine<SecretKey, Ciphertext>,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(benchmark_name!(impl GlweCiphertextInplaceDecryptionEngine<
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
                let (glwe_dim, poly_size) = param.to_owned();
                let mut plaintext_vector = util_engine
                    .create_plaintext_vector(UtilRaw::any_vec(poly_size.0).as_slice())
                    .unwrap();
                let secret_key = util_engine
                    .generate_glwe_secret_key(glwe_dim, poly_size)
                    .unwrap();
                let ciphertext = util_engine
                    .zero_encrypt_glwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_decrypt_glwe_ciphertext_unchecked(
                            black_box(&secret_key),
                            black_box(&mut plaintext_vector),
                            black_box(&ciphertext),
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
const PARAMETERS: [(GlweDimension, PolynomialSize); 5] = [
    (GlweDimension(1), PolynomialSize(256)),
    (GlweDimension(1), PolynomialSize(512)),
    (GlweDimension(1), PolynomialSize(1024)),
    (GlweDimension(1), PolynomialSize(2048)),
    (GlweDimension(1), PolynomialSize(4096)),
];
