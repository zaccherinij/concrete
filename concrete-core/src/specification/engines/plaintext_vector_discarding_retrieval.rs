use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorDiscardingRetrievalError for PlaintextVectorDiscardingRetrievalEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same."
}

/// A trait for engines retrieving (discarding) arbitrary values from plaintext vectors.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` arbitrary value slice with the
/// element-wise retrieval of the `input` plaintext vector values.
///
/// # Formal Definition
pub trait PlaintextVectorDiscardingRetrievalEngine<PlaintextVector, Value>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Retrieves arbitrary values from a plaintext vector.
    fn discarding_retrieve_plaintext_vector(
        &mut self,
        output: &mut [Value],
        input: &PlaintextVector,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves arbitrary values from a plaintext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorDiscardingRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discarding_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [Value],
        input: &PlaintextVector,
    );
}
