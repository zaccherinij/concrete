use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorInplaceNegationError for LweCiphertextVectorInplaceNegationEngine @
    LweDimensionMismatch => "The input and output lwe dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphretext count must be the same."
}

/// A trait for engines negating (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the element-wise negation of the `input` lwe ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceNegationEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = InputCiphertextVector::KeyFlavor,
        Representation = InputCiphertextVector::Representation,
    >,
{
    /// Negates an lwe ciphertext vector.
    fn inplace_neg_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorInplaceNegationError<Self::EngineError>>;

    /// Unsafely negates an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceNegationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_neg_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
