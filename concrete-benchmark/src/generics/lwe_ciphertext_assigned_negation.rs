use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::LweDimension;
use concrete_core::specification::engines::{
    LweCiphertextAssignedNegationEngine, LweCiphertextZeroEncryptionEngine,
    LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the assigned lwe negation operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,        // The benchmarked engine implementing the inplace lwe negation trait.
    Ciphertext,    // The lwe ciphertext type.
    UtilEngine,    // The util engine used to generate all operator inputs.
    UtilSecretKey, // The util secret key used to generate the ciphertext.
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextAssignedNegationEngine<Ciphertext>,
    Ciphertext: LweCiphertextEntity,
    UtilEngine: LweCiphertextZeroEncryptionEngine<UtilSecretKey, Ciphertext>
        + LweSecretKeyGenerationEngine<UtilSecretKey>,
    UtilSecretKey: LweSecretKeyEntity<
        KeyFlavor = Ciphertext::KeyFlavor,
        Representation = Ciphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(
        benchmark_name!(impl LweCiphertextAssignedNegationEngine<Ciphertext> for Engine),
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
                b.iter(|| {
                    unsafe {
                        engine.assigned_neg_lwe_ciphertext_unchecked(black_box(&mut output));
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
