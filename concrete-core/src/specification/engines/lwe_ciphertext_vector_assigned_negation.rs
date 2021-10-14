use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorAssignedNegationError for LweCiphertextVectorAssignedNegationEngine @
}

/// A trait for engines negating (assign) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation negates the `input` lwe ciphertext vector.
///
///  # Formal Definition
pub trait LweCiphertextVectorAssignedNegationEngine<CiphertextVector>: AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
{
    /// Negates an lwe ciphertext vector.
    fn assign_neg_lwe_ciphertext_vector(
        &mut self,
        input: &mut CiphertextVector,
    ) -> Result<(), LweCiphertextVectorAssignedNegationError<Self::EngineError>>;

    /// Unsafely negates an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorAssignedNegationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn assign_neg_lwe_ciphertext_vector_unchecked(&mut self, input: &mut CiphertextVector);
}
