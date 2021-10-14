use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorInplaceAdditionError for LweCiphertextVectorInplaceAdditionEngine @
    LweDimensionMismatch => "The input and output lwe dimensions must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

/// A trait for engines adding (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the element-wise addition of the `input_1` lwe ciphertext vector and the `input_2` lwe
/// ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceAdditionEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = InputCiphertextVector::KeyFlavor,
        Representation = InputCiphertextVector::Representation,
    >,
{
    /// Adds two lwe ciphertext vectors.
    fn inplace_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorInplaceAdditionError<Self::EngineError>>;

    /// Unsafely adds two lwe ciphertext vectors.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceAdditionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input_1: &InputCiphertextVector,
        input_2: &InputCiphertextVector,
    );
}
