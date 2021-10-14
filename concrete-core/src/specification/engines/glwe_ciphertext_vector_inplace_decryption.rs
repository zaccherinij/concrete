use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextVectorInplaceDecryptionError for GlweCiphertextVectorInplaceDecryptionEngine @
    GlweDimensionMismatch => "The glwe dimensions of the key and the input ciphertext must be the \
                              same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the input ciphertext must be the \
                               same.",
    PlaintextCountMismatch => "The input plaintext vector length and input ciphertext vector \
                               capacity (poly size * length) must be the same."
}

/// A trait for engines decrypting (inplace) glwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext vector  
/// with the piece-wise decryptions of the `input` glwe ciphertext vector, under the `key` secret
/// key.
///
/// # Formal Definition
pub trait GlweCiphertextVectorInplaceDecryptionEngine<SecretKey, CiphertextVector, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    CiphertextVector: GlweCiphertextVectorEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
{
    /// Decrypts a glwe ciphertext vector inplace.
    fn inplace_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    ) -> Result<(), GlweCiphertextVectorInplaceDecryptionError<Self::EngineError>>;

    /// Unsafely encrypts a glwe ciphertext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorInplaceDecryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &CiphertextVector,
    );
}
