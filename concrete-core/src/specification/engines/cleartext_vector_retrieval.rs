use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorRetrievalError for CleartextVectorRetrievalEngine @
}

/// A trait for engines retrieving cleartext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a vec of raw values from the `input`
/// cleartext vector.
///
/// # Formal Definition
pub trait CleartextVectorRetrievalEngine<CleartextVector, Raw>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Retrieves raw values from a cleartext vector.
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector,
    ) -> Result<Vec<Raw>, CleartextVectorRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves raw values from a cleartext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector,
    ) -> Vec<Raw>;
}
