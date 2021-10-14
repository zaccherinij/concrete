use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorAssignedAdditionError for LweCiphertextVectorAssignedAdditionEngine @
    LweDimensionMismatch => "The input and output lwe dimension must be the same.",
    CiphertextCountMismatch => "The input and output vectors length must be the same."
}

/// A trait for engines adding (assign) lwe ciphertexts vectors.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation adds the `input` lwe ciphertext vector to
/// the `output` lwe ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorAssignedAdditionEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = InputCiphertextVector::KeyFlavor,
        Representation = InputCiphertextVector::Representation,
    >,
{
    /// Add two lwe ciphertext vectors.
    fn assign_add_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    ) -> Result<(), LweCiphertextVectorAssignedAdditionError<Self::EngineError>>;

    /// Unsafely add two lwe ciphertext vectors.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorAssignedAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn assign_add_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
    );
}
