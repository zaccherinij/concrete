use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextDiscardingDecryptionError for GlweCiphertextDiscardingDecryptionEngine @
    GlweDimensionMismatch => "The GLWE dimension of the key and ciphertext must be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and ciphertext must be the same.",
    PlaintextCountMismatch => "The size of the output plaintext vector and the input ciphertext \
                               polynomial size must be the same."
}

/// A trait for engines decrypting (discarding) GLWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` plaintext vector with the
/// decryption of the `input` GLWE ciphertext, under the `key` secret key.
///
/// # Formal Definition
pub trait GlweCiphertextDiscardingDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity<KeyFlavor = SecretKey::KeyFlavor>,
    PlaintextVector: PlaintextVectorEntity,
{
    /// Decrypts a GLWE ciphertext .
    fn discard_decrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &Ciphertext,
    ) -> Result<(), GlweCiphertextDiscardingDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a GLWE ciphertext .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextDiscardingDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &Ciphertext,
    );
}
