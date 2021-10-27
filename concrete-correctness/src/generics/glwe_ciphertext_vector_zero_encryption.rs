use crate::utils::{assert_delta_std_dev, RawUnsignedIntegers};
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::parameters::{
    CiphertextCount, GlweCiphertextCount, GlweDimension, PolynomialSize,
};
use concrete_core::specification::engines::{
    GlweCiphertextDecryptionEngine, GlweCiphertextEncryptionEngine,
    GlweCiphertextVectorDecryptionEngine, GlweCiphertextVectorEncryptionEngine,
    GlweCiphertextVectorZeroEncryptionEngine, GlweSecretKeyGenerationEngine,
    PlaintextVectorCreationEngine, PlaintextVectorInplaceRetrievalEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

/// A generic function testing the glwe vector zero encryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,              // The tested engine, implementing the encryption trait
    SecretKey,           // The secret key type
    CiphertextVector,    // The glwe ciphertext vector type
    UtilEngine,          // The util engine used to generate all operator inputs
    UtilPlaintextVector, // The plaintext vector type
    UtilRaw,             // The raw numeric type used to generate the plaintext.
>()
where
    Engine: GlweCiphertextVectorZeroEncryptionEngine<SecretKey, CiphertextVector>,
    SecretKey: GlweSecretKeyEntity,
    CiphertextVector: GlweCiphertextVectorEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: GlweCiphertextVectorDecryptionEngine<SecretKey, CiphertextVector, UtilPlaintextVector>
        + GlweSecretKeyGenerationEngine<SecretKey>
        + PlaintextVectorCreationEngine<UtilRaw, UtilPlaintextVector>
        + PlaintextVectorInplaceRetrievalEngine<UtilPlaintextVector, UtilRaw>,
    UtilPlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    UtilRaw: RawUnsignedIntegers,
{
    let VARIANCE = Variance(LogStandardDev::from_log_standard_dev(-20.).get_variance());

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for (glwe_dimension, polynomial_size, ciphertext_count) in PARAMETERS {
        let inputs = UtilRaw::zero_vec(ciphertext_count.0 * polynomial_size.0);
        let secret_key = util_engine
            .generate_glwe_secret_key(glwe_dimension, polynomial_size)
            .unwrap();
        let encrypted = engine
            .zero_encrypt_glwe_ciphertext_vector(
                &secret_key,
                VARIANCE,
                GlweCiphertextCount(ciphertext_count.0),
            )
            .unwrap();
        let decrypted_plaintext_vector = util_engine
            .decrypt_glwe_ciphertext_vector(&secret_key, &encrypted)
            .unwrap();

        let mut outputs = UtilRaw::one_vec(ciphertext_count.0 * polynomial_size.0);
        util_engine
            .inplace_retrieve_plaintext_vector(outputs.as_mut_slice(), &decrypted_plaintext_vector)
            .unwrap();
        assert_delta_std_dev(&inputs, &outputs, VARIANCE);
    }
}

/// The parameters the test is executed against.
const PARAMETERS: [(GlweDimension, PolynomialSize, CiphertextCount); 1] =
    [(GlweDimension(200), PolynomialSize(200), CiphertextCount(20))];
