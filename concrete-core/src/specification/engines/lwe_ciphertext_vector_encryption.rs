use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweCiphertextVectorEncryptionError for LweCiphertextVectorEncryptionEngine @
}

/// A trait for engines encrypting lwe ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an lwe ciphertext vector containing
/// the element-wise encryption of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
pub trait LweCiphertextVectorEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    CiphertextVector: LweCiphertextVectorEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
{
    /// Encrypts an lwe ciphertext vector.
    fn encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<CiphertextVector, LweCiphertextVectorEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &PlaintextVector,
        noise: Variance,
    ) -> CiphertextVector;
}
