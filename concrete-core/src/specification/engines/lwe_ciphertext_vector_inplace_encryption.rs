use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweCiphertextVectorInplaceEncryptionError for LweCiphertextVectorInplaceEncryptionEngine @
    LweDimensionMismatch => "The key and output lwe dimensions must be the same.",
    PlaintextCountMismatch => "The input length and output ciphertext count must be the same."
}

/// A trait for engines encrypting (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the element-wise encryption of the `input` plaintext vector under the `key` lwe secret key.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
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
    fn inplace_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorInplaceEncryptionError<Self::EngineError>>;

    /// Unsafely encryprs an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    );
}
