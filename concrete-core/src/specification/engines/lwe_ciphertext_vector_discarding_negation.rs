use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorDiscardingNegationError for LweCiphertextVectorDiscardingNegationEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

/// A trait for engines negating (discarding) LWE ciphertext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext vector
/// with the element-wise negation of the `input` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingNegationEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<KeyFlavor = InputCiphertextVector::KeyFlavor>,
{
    /// Negates an LWE ciphertext vector.
    fn discard_neg_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorDiscardingNegationError<Self::EngineError>>;

    /// Unsafely negates an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingNegationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_neg_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
