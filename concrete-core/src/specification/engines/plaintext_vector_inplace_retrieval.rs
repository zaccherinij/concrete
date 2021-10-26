use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorInplaceRetrievalError for PlaintextVectorInplaceRetrievalEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same."
}

/// A trait for engines retrieving (inplace) plaintext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` raw value slice with the
/// element-wise retrieval of the `input` plaintext vector values.
///
/// # Formal Definition
pub trait PlaintextVectorInplaceRetrievalEngine<PlaintextVector, Raw>: AbstractEngine
where
    PlaintextVector: PlaintextVectorEntity,
{
    /// Retrieves raw values from a plaintext vector inplace.
    fn inplace_retrieve_plaintext_vector(
        &mut self,
        output: &mut [Raw],
        input: &PlaintextVector,
    ) -> Result<(), PlaintextVectorInplaceRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves raw values from a plaintext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorInplaceRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [Raw],
        input: &PlaintextVector,
    );
}
