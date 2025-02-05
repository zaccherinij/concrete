use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweCiphertextVectorDiscardingEncryptionError for LweCiphertextVectorDiscardingEncryptionEngine @
    LweDimensionMismatch => "The key and output LWE dimensions must be the same.",
    PlaintextCountMismatch => "The input plaintext count and the output ciphertext count must be \
                               the same."
}

/// A trait for engines encrypting (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise encryption of the `input` plaintext vector under the `key` LWE secret key.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingEncryptionEngine<
    SecretKey,
    PlaintextVector,
    CiphertextVector,
>: AbstractEngine where
    SecretKey: LweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity,
    CiphertextVector: LweCiphertextVectorEntity<KeyFlavor = SecretKey::KeyFlavor>,
{
    /// Encrypts an LWE ciphertext vector.
    fn discard_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorDiscardingEncryptionError<Self::EngineError>>;

    /// Unsafely encryprs an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    );
}
