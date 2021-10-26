use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorInplaceRetrievalError for CleartextVectorInplaceRetrievalEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same."
}

/// A trait for engines retrieving (inplace) cleartext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` raw value slice with the
/// element-wise retrieval of the `input` cleartext vector values.
///
/// # Formal Definition
pub trait CleartextVectorInplaceRetrievalEngine<CleartextVector, Raw>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Retrieves raw values from a cleartext vector inplace.
    fn inplace_retrieve_cleartext_vector(
        &mut self,
        output: &mut [Raw],
        input: &CleartextVector,
    ) -> Result<(), CleartextVectorInplaceRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves raw values from a cleartext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorInplaceRetrievalError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [Raw],
        input: &CleartextVector,
    );
}
