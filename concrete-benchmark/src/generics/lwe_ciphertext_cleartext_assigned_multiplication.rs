use crate::utils::{benchmark_name, RawNumeric};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    CleartextCreationEngine, LweCiphertextCleartextAssignedMultiplicationEngine,
    LweCiphertextZeroEncryptionEngine, LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    CleartextEntity, LweCiphertextEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the assigned lwe cleartext multiplication operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,        // The benchmarked engine, implementing the multiplication trait.
    Ciphertext,    // The lwe ciphertext type.
    Cleartext,     // The cleartext type.
    UtilEngine,    // The util engine used to generate all operator inputs.
    UtilRaw,       // A raw numeric type used to generate the cleartexts.
    UtilSecretKey, // A util secret key used to generate the ciphertext.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextCleartextAssignedMultiplicationEngine<Ciphertext, Cleartext>,
    Ciphertext: LweCiphertextEntity,
    Cleartext: CleartextEntity<Representation = Ciphertext::Representation>,
    UtilEngine: LweSecretKeyGenerationEngine<UtilSecretKey>
        + LweCiphertextZeroEncryptionEngine<UtilSecretKey, Ciphertext>
        + CleartextCreationEngine<UtilRaw, Cleartext>,
    UtilRaw: RawNumeric,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = Ciphertext::KeyFlavor,
        Representation = Ciphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextCleartextAssignedMultiplicationEngine<
            Ciphertext, 
            Cleartext
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
                let input_2 = util_engine.create_cleartext(&UtilRaw::any()).unwrap();

                b.iter(|| {
                    unsafe {
                        engine.assign_mul_lwe_ciphertext_cleartext_unchecked(
                            black_box(&mut output),
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
