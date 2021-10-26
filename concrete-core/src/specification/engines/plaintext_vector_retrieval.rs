use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorRetrievalError for PlaintextVectorRetrievalEngine @
}

/// A trait for engines retrieving plaintext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of raw values from the `input`
/// plaintext vector.
///
/// # Formal Definition
pub trait PlaintextVectorRetrievalEngine<PlaintextVector, Raw>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Retrieves raw values from a plaintext vector.
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector,
    ) -> Result<Vec<Raw>, PlaintextVectorRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves raw values from a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector,
    ) -> Vec<Raw>;
}
