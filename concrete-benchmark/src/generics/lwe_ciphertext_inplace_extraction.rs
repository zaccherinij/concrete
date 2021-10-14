use crate::utils::benchmark_name;
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{GlweDimension, LweDimension, MonomialDegree, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextZeroEncryptionEngine, GlweSecretKeyGenerationEngine,
    LweCiphertextInplaceExtractionEngine, LweCiphertextZeroEncryptionEngine,
    LweSecretKeyGenerationEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, LweCiphertextEntity, LweSecretKeyEntity,
};
use criterion::{black_box, BenchmarkId, Criterion};

/// A generic function benchmarking the inplace lwe sample extraction.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the benchmark, but are needed to generate
/// the entities that the operation will execute on.
pub fn bench<
    Engine,         // The benchmarked engine, implementing the sample extraction trait.
    GlweCiphertext, // The glwe ciphertext type.
    LweCiphertext,  // The lwe ciphertext type.
    UtilEngine,     // The util engine used to generate all operator inputs.
    UtilLweSk,      // The util lwe secret key used to generate lwe ciphertexts
    UtilGlweSk,     // The util glwe secret key used to generate glwe ciphertexts
>(
    c: &mut Criterion,
) where
    Engine: LweCiphertextInplaceExtractionEngine<GlweCiphertext, LweCiphertext>,
    GlweCiphertext: GlweCiphertextEntity,
    LweCiphertext: LweCiphertextEntity<
        KeyFlavor = GlweCiphertext::KeyFlavor,
        Representation = GlweCiphertext::Representation,
    >,
    UtilEngine: LweSecretKeyGenerationEngine<UtilLweSk>
        + GlweSecretKeyGenerationEngine<UtilGlweSk>
        + LweCiphertextZeroEncryptionEngine<UtilLweSk, LweCiphertext>
        + GlweCiphertextZeroEncryptionEngine<UtilGlweSk, GlweCiphertext>,
    UtilLweSk: LweSecretKeyEntity<
        KeyFlavor = GlweCiphertext::KeyFlavor,
        Representation = GlweCiphertext::Representation,
    >,
    UtilGlweSk: GlweSecretKeyEntity<
        KeyFlavor = GlweCiphertext::KeyFlavor,
        Representation = GlweCiphertext::Representation,
    >,
{
    let mut group = c.benchmark_group(benchmark_name!(impl LweCiphertextInplaceExtractionEngine<
            GlweCiphertext, 
            LweCiphertext
            > for Engine));

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for param in PARAMETERS {
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{:?}", param)),
            &param,
            |b, param| {
                let (glwe_dim, poly_size) = param.to_owned();
                let lwe_dim = LweDimension(glwe_dim.0 * poly_size.0);
                let lwe_sk = util_engine.generate_lwe_secret_key(lwe_dim).unwrap();
                let glwe_sk = util_engine
                    .generate_glwe_secret_key(glwe_dim, poly_size)
                    .unwrap();
                let mut lwe_ciphertext = util_engine
                    .zero_encrypt_lwe_ciphertext(&lwe_sk, VARIANCE)
                    .unwrap();
                let glwe_ciphertext = util_engine
                    .zero_encrypt_glwe_ciphertext(&glwe_sk, VARIANCE)
                    .unwrap();

                b.iter(|| {
                    unsafe {
                        engine.inplace_extract_lwe_ciphertext_unchecked(
                            black_box(&mut lwe_ciphertext),
                            black_box(&glwe_ciphertext),
                            black_box(MonomialDegree(1)),
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
const PARAMETERS: [(GlweDimension, PolynomialSize); 10] = [
    (GlweDimension(1), PolynomialSize(256)),
    (GlweDimension(1), PolynomialSize(512)),
    (GlweDimension(1), PolynomialSize(1024)),
    (GlweDimension(1), PolynomialSize(2048)),
    (GlweDimension(1), PolynomialSize(4096)),
    (GlweDimension(3), PolynomialSize(256)),
    (GlweDimension(3), PolynomialSize(512)),
    (GlweDimension(3), PolynomialSize(1024)),
    (GlweDimension(3), PolynomialSize(2048)),
    (GlweDimension(3), PolynomialSize(4096)),
];
