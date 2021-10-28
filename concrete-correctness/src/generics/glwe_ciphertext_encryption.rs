use crate::utils::{assert_delta_std_dev, RawUnsignedIntegers};
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::parameters::{CiphertextCount, GlweDimension, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextDecryptionEngine, GlweCiphertextEncryptionEngine, GlweSecretKeyGenerationEngine,
    PlaintextVectorCreationEngine, PlaintextVectorInplaceRetrievalEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

/// A generic function testing the glwe encryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,          // The tested engine, implementing the encryption trait
    SecretKey,       // The secret key type
    PlaintextVector, // The plaintext vector type
    Ciphertext,      // The glwe ciphertext type
    UtilEngine,      // The util engine used to generate all operator inputs
    UtilRaw,         // The raw numeric type used to generate the plaintext.
>()
where
    Engine: GlweCiphertextEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>,
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    Ciphertext: GlweCiphertextEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: GlweCiphertextDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>
        + GlweSecretKeyGenerationEngine<SecretKey>
        + PlaintextVectorCreationEngine<UtilRaw, PlaintextVector>
        + PlaintextVectorInplaceRetrievalEngine<PlaintextVector, UtilRaw>,
    UtilRaw: RawUnsignedIntegers,
{
    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for (glwe_dimension, polynomial_size, ciphertext_count) in PARAMETERS {
        let inputs = UtilRaw::uniform_vec(ciphertext_count.0 * polynomial_size.0);
        let mut outputs = UtilRaw::one_vec(ciphertext_count.0 * polynomial_size.0);
        let secret_key = util_engine
            .generate_glwe_secret_key(glwe_dimension, polynomial_size)
            .unwrap();
        for ith in (0..ciphertext_count.0) {
            let index_range = ith * polynomial_size.0..(ith + 1) * polynomial_size.0;
            let plaintext_vector = util_engine
                .create_plaintext_vector(&inputs.as_slice()[index_range.clone()])
                .unwrap();
            let encrypted = engine
                .encrypt_glwe_ciphertext(&secret_key, &plaintext_vector, VARIANCE)
                .unwrap();
            let decrypted_plaintext_vector = util_engine
                .decrypt_glwe_ciphertext(&secret_key, &encrypted)
                .unwrap();
            util_engine
                .inplace_retrieve_plaintext_vector(
                    &mut outputs.as_mut_slice()[index_range],
                    &decrypted_plaintext_vector,
                )
                .unwrap()
        }
        assert_delta_std_dev(&inputs, &outputs, VARIANCE);
    }
}

/// The variance used to encrypt everything in the test (log std = -20)
const VARIANCE: Variance = Variance(0.0000000000009094947017729282);

/// The parameters the test is executed against.
const PARAMETERS: [(GlweDimension, PolynomialSize, CiphertextCount); 1] =
    [(GlweDimension(200), PolynomialSize(200), CiphertextCount(20))];
