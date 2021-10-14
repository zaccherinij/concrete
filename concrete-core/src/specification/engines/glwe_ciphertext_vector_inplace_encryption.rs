use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    GlweCiphertextVectorInplaceEncryptionError for GlweCiphertextVectorInplaceEncryptionEngine @
    GlweDimensionMismatch => "The glwe dimensions of the key and the output ciphertext must be the \
                              same.",
    PolynomialSizeMismatch => "The polynomial size of the key and the output ciphertext must be the \
                               same.",
    PlaintextCountMismatch => "The input plaintext vector length and output ciphertext vector \
                               capacity (poly size * length) must be the same."
}

/// A trait for engines encrypting (inplace) glwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` glwe ciphertext vector
/// with the piece-wise encryptions of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
pub trait GlweCiphertextVectorInplaceEncryptionEngine<SecretKey, PlaintextVector, CiphertextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    CiphertextVector: GlweCiphertextVectorEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
{
    /// Encrypts a glwe ciphertext vector inplace.
    fn inplace_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorInplaceEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a glwe ciphertext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorInplaceEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut CiphertextVector,
        input: &PlaintextVector,
        noise: Variance,
    );
}
