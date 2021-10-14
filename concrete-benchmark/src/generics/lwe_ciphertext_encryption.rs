use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    LweCiphertextEncryptionEngine, LweSecretKeyGenerationEngine, PlaintextCreationEngine,
};

use concrete_core::specification::entities::{
    LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the lwe encryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,     // The benchmarked engine, implementing the encryption trait.
    SecretKey,  // The lwe secret key type.
    Plaintext,  // The plaintext type
    Ciphertext, // The lwe ciphertext type.
    UtilEngine, // The util engine used to generate all operator inputs.
    UtilRaw,    // A raw numeric type used to generate the plaintext.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextEncryptionEngine<SecretKey, Plaintext, Ciphertext>,
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity<Representation = SecretKey::Representation>,
    Ciphertext: LweCiphertextEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine:
        PlaintextCreationEngine<UtilRaw, Plaintext> + LweSecretKeyGenerationEngine<SecretKey>,
    UtilRaw: RawNumeric,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextEncryptionEngine<SecretKey, Plaintext, Ciphertext> for Engine),
    );

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let lwe_dim = param.to_owned();
                let plaintext = util_engine.create_plaintext(&UtilRaw::any()).unwrap();
                let secret_key = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                b.iter(|| {
                    unsafe {
                        black_box(engine.encrypt_lwe_ciphertext_unchecked(
                            black_box(&secret_key),
                            black_box(&plaintext),
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
const PARAMETERS: [LweDimension; 6] = [
    (LweDimension(100)),
    (LweDimension(300)),
    (LweDimension(600)),
    (LweDimension(1000)),
    (LweDimension(3000)),
    (LweDimension(6000)),
];
