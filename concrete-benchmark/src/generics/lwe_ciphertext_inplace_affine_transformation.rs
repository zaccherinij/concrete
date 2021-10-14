use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
use concrete_core::specification::engines::{
    CleartextVectorCreationEngine, LweCiphertextInplaceAffineTransformationEngine,
    LweCiphertextVectorZeroEncryptionEngine, LweCiphertextZeroEncryptionEngine,
    LweSecretKeyGenerationEngine, PlaintextCreationEngine,
};
use concrete_core::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity, LweSecretKeyEntity,
    PlaintextEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe affine transform operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,           // The benchmarked engine implementing the lwe multisum trait.
    CiphertextVector, // The input lwe ciphertext vector type.
    CleartextVector,  // The cleartext vector weights type.
    Plaintext,        // The plaintext bias type.
    OutputCiphertext, // The output lwe ciphertext type.
    UtilEngine,       // The utility engine used to generate ciphertexts, plaintext and cleartext.
    UtilRaw,          // The raw numeric type used to construct plaintext and cleartext.
    UtilSecretKey,    // The secret key used to generate the ciphertext and ciphertexts vector.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextInplaceAffineTransformationEngine<
        CiphertextVector,
        CleartextVector,
        Plaintext,
        OutputCiphertext,
    >,
    OutputCiphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity<
        Representation = OutputCiphertext::Representation,
        KeyFlavor = OutputCiphertext::KeyFlavor,
    >,
    CleartextVector: CleartextVectorEntity<Representation = OutputCiphertext::Representation>,
    Plaintext: PlaintextEntity<Representation = OutputCiphertext::Representation>,
    UtilEngine: LweCiphertextZeroEncryptionEngine<UtilSecretKey, OutputCiphertext>
        + LweCiphertextVectorZeroEncryptionEngine<UtilSecretKey, CiphertextVector>
        + LweSecretKeyGenerationEngine<UtilSecretKey>
        + CleartextVectorCreationEngine<UtilRaw, CleartextVector>
        + PlaintextCreationEngine<UtilRaw, Plaintext>,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = OutputCiphertext::KeyFlavor,
        Representation = OutputCiphertext::Representation,
    >,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextInplaceAffineTransformationEngine<
            CiphertextVector, 
            CleartextVector, 
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
                let (lwe_dim, ciphertext_count) = param.to_owned();
                let secret_key = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                let mut output = util_engine
                    .zero_encrypt_lwe_ciphertext(&secret_key, VARIANCE)
                    .unwrap();
                let inputs = util_engine
                    .zero_encrypt_lwe_ciphertext_vector(&secret_key, VARIANCE, ciphertext_count)
                    .unwrap();
                let weights = util_engine
                    .create_cleartext_vector(UtilRaw::any_vec(ciphertext_count.0).as_slice())
                    .unwrap();
                let bias = util_engine.create_plaintext(&UtilRaw::any()).unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_affine_transform_lwe_ciphertext_unchecked(
                            black_box(&mut output),
                            black_box(&inputs),
                            black_box(&weights),
                            black_box(&bias),
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
    (LweDimension(100), LweCiphertextCount(10)),
    (LweDimension(300), LweCiphertextCount(10)),
    (LweDimension(600), LweCiphertextCount(10)),
    (LweDimension(1000), LweCiphertextCount(10)),
    (LweDimension(3000), LweCiphertextCount(10)),
    (LweDimension(6000), LweCiphertextCount(10)),
];
