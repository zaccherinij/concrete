use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    LweCiphertextVectorInplaceDecryptionError for LweCiphertextVectorInplaceDecryptionEngine @
    LweDimensionMismatch => "The key and output lwe dimensions must be the same.",
    PlaintextCountMismatch => "The output length and input ciphertext count must be the same."
}

/// A trait for engines decrypting (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext vector
/// with the element-wise decryption of the `input` lwe ciphertext vector under the `key` lwe secret
/// key.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>:
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
    fn inplace_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), LweCiphertextVectorInplaceDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    );
}
