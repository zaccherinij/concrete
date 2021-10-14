use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorCreationError for PlaintextVectorCreationEngine @
    EmptyInput => "The input slice must not be empty."
}

/// A trait for engines creating plaintext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext vector from the `input`
/// slice of raw values.
///
/// # Formal Definition
pub trait PlaintextVectorCreationEngine<Raw, PlaintextVector>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Creates a plaintext vector from a slice of raw values.
    fn create_plaintext_vector(
        &mut self,
        input: &[Raw],
    ) -> Result<PlaintextVector, PlaintextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates a plaintext vector from a slice of raw values.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_plaintext_vector_unchecked(&mut self, input: &[Raw]) -> PlaintextVector;
}
