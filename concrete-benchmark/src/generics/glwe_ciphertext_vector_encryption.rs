use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextVectorEncryptionEngine, GlweSecretKeyGenerationEngine,
    PlaintextVectorCreationEngine,
};

use concrete_core::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the glwe vector encryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine, implementing the encryption trait.
    SecretKey,        // The glwe secret key type.
    PlaintextVector,  // The plaintext vector type.
    CiphertextVector, // The glwe ciphertext vector type.
    UtilEngine,       // The util engine used to generate all operator inputs.
    UtilRaw,          // The raw numeric type used to generate the plaintext vector.
>(
    c: &mut Criterion,
) where
    Engine: GlweCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>,
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    CiphertextVector: GlweCiphertextVectorEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: PlaintextVectorCreationEngine<UtilRaw, PlaintextVector>
        + GlweSecretKeyGenerationEngine<SecretKey>,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(benchmark_name!(impl GlweCiphertextVectorEncryptionEngine<
        SecretKey,
        PlaintextVector,
        CiphertextVector
        > for Engine
    ));

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (glwe_dim, poly_size, ciphertext_count) = param.to_owned();
                let plaintext_vector = util_engine
                    .create_plaintext_vector(
                        UtilRaw::any_vec(poly_size.0 * ciphertext_count.0).as_slice(),
                    )
                    .unwrap();
                let secret_key = util_engine
                    .generate_glwe_secret_key(glwe_dim, poly_size)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        black_box(engine.encrypt_glwe_ciphertext_vector_unchecked(
                            black_box(&secret_key),
                            black_box(&plaintext_vector),
                            black_box(VARIANCE),
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
const PARAMETERS: [(GlweDimension, PolynomialSize, GlweCiphertextCount); 5] = [
    (
        GlweDimension(1),
        PolynomialSize(256),
        GlweCiphertextCount(100),
    ),
    (
        GlweDimension(1),
        PolynomialSize(512),
        GlweCiphertextCount(100),
    ),
    (
        GlweDimension(1),
        PolynomialSize(1024),
        GlweCiphertextCount(100),
    ),
    (
        GlweDimension(1),
        PolynomialSize(2048),
        GlweCiphertextCount(100),
    ),
    (
        GlweDimension(1),
        PolynomialSize(4096),
        GlweCiphertextCount(100),
    ),
];
