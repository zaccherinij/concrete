use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
use concrete_core::specification::engines::{
    LweCiphertextVectorInplaceEncryptionEngine, LweCiphertextVectorZeroEncryptionEngine,
    LweSecretKeyGenerationEngine, PlaintextVectorCreationEngine,
};

use concrete_core::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe vector encryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine, implementing the lwe vector encryption.
    SecretKey,        // The lwe secret key type.
    PlaintextVector,  // The plaintext vector type.
    CiphertextVector, // The lwe vector type.
    UtilEngine,       // The utility engine used to generate all operator inputs.
    UtilRaw,          // The raw numeric type used for the plaintexts.
>(
    c: &mut Criterion,
) where
    Engine:
        LweCiphertextVectorInplaceEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>,
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    CiphertextVector: LweCiphertextVectorEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    UtilEngine: PlaintextVectorCreationEngine<UtilRaw, PlaintextVector>
        + LweSecretKeyGenerationEngine<SecretKey>
        + LweCiphertextVectorZeroEncryptionEngine<SecretKey, CiphertextVector>,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextVectorInplaceEncryptionEngine<
            SecretKey,
            PlaintextVector,
            CiphertextVector
            > for Engine),
    );

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (lwe_dim, ciphertext_count) = param.to_owned();
                let plaintext_vector = util_engine
                    .create_plaintext_vector(UtilRaw::any_vec(ciphertext_count.0).as_slice())
                    .unwrap();
                let secret_key = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                let mut output = util_engine
                    .zero_encrypt_lwe_ciphertext_vector(&secret_key, VARIANCE, param.1)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_encrypt_lwe_ciphertext_vector_unchecked(
                            black_box(&secret_key),
                            black_box(&mut output),
                            black_box(&plaintext_vector),
                            black_box(VARIANCE),
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
const PARAMETERS: [(LweDimension, LweCiphertextCount); 6] = [
    (LweDimension(100), LweCiphertextCount(100)),
    (LweDimension(300), LweCiphertextCount(100)),
    (LweDimension(600), LweCiphertextCount(100)),
    (LweDimension(1000), LweCiphertextCount(100)),
    (LweDimension(3000), LweCiphertextCount(100)),
    (LweDimension(6000), LweCiphertextCount(100)),
];
