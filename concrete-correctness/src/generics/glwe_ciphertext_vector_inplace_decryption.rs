use crate::utils::{assert_delta_std_dev, RawUnsignedIntegers};
use concrete_commons::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_commons::parameters::{CiphertextCount, GlweDimension, PolynomialSize};
use concrete_core::specification::engines::{
    GlweCiphertextDecryptionEngine, GlweCiphertextEncryptionEngine,
    GlweCiphertextInplaceDecryptionEngine, GlweCiphertextVectorEncryptionEngine,
    GlweCiphertextVectorInplaceDecryptionEngine, GlweCiphertextZeroEncryptionEngine,
    GlweSecretKeyGenerationEngine, PlaintextVectorCreationEngine,
    PlaintextVectorInplaceRetrievalEngine, PlaintextVectorRetrievalEngine,
};
use concrete_core::specification::entities::{
    GlweCiphertextEntity, GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

/// A generic function testing the inplace glwe vector decryption operation.
///
/// # Note:
///
/// Type parameters prefixed with `Util` are not used in the test, but are needed to generate
/// the entities that the operation will execute on.
pub fn test<
    Engine,           // The tested engine, implementing the inplace decryption trait
    SecretKey,        // The secret key type
    CiphertextVector, // The glwe ciphertext vector type
    PlaintextVector,  // The plaintext vector type
    UtilEngine,       // The util engine used to generate all operator inputs
    UtilRaw,          // The util raw type used to create plaintexts
>()
where
    Engine:
        GlweCiphertextVectorInplaceDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>,
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    CiphertextVector: GlweCiphertextVectorEntity<
        KeyFlavor = SecretKey::KeyFlavor,
        Representation = SecretKey::Representation,
    >,
    UtilEngine: GlweCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>
        + GlweSecretKeyGenerationEngine<SecretKey>
        + PlaintextVectorCreationEngine<UtilRaw, PlaintextVector>
        + PlaintextVectorInplaceRetrievalEngine<PlaintextVector, UtilRaw>,
    UtilRaw: RawUnsignedIntegers,
{
    let VARIANCE = Variance(LogStandardDev::from_log_standard_dev(-20.).get_variance());

    let mut engine = Engine::new().unwrap();
    let mut util_engine = UtilEngine::new().unwrap();

    for (glwe_dimension, polynomial_size, ciphertext_count) in PARAMETERS {
        let inputs = UtilRaw::uniform_vec(ciphertext_count.0 * polynomial_size.0);
        let secret_key = util_engine
            .generate_glwe_secret_key(glwe_dimension, polynomial_size)
            .unwrap();
        let mut decrypted_plaintext_vector = util_engine
            .create_plaintext_vector(
                UtilRaw::one_vec(polynomial_size.0 * ciphertext_count.0).as_slice(),
            )
            .unwrap();
        let plaintext_vector = util_engine
            .create_plaintext_vector(inputs.as_slice())
            .unwrap();
        let encrypted = util_engine
            .encrypt_glwe_ciphertext_vector(&secret_key, &plaintext_vector, VARIANCE)
            .unwrap();
        engine
            .inplace_decrypt_glwe_ciphertext_vector(
                &secret_key,
                &mut decrypted_plaintext_vector,
                &encrypted,
            )
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
