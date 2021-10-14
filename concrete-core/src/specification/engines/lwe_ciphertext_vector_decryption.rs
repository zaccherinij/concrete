use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorDecryptionError for LweCiphertextVectorDecryptionEngine @
}

/// A trait for engines decrypting lwe ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector containing
/// the element-wise decryption of the `input` lwe ciphertext vector under the `key` secret key.
///
/// # Formal Definition
pub trait LweCiphertextVectorDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    CiphertextVector: LweCiphertextVectorEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
{
    /// Decrypts an lwe ciphertext vector.
    fn decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> Result<PlaintextVector, LweCiphertextVectorDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        input: &CiphertextVector,
    ) -> PlaintextVector;
}
