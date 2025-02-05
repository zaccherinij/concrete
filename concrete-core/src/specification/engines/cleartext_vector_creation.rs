use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorCreationError for CleartextVectorCreationEngine @
    EmptyInput => "The input slice must not be empty."
}

/// A trait for engines creating cleartext vectors from arbitrary values.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext vector from the `value`
/// slice of arbitrary values.
///
/// # Formal Definition
pub trait CleartextVectorCreationEngine<Value, CleartextVector>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Creates a cleartext vector from a slice of arbitrary values.
    fn create_cleartext_vector(
        &mut self,
        values: &[Value],
    ) -> Result<CleartextVector, CleartextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates a cleartext vector from a slice of arbitrary values.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_cleartext_vector_unchecked(&mut self, values: &[Value]) -> CleartextVector;
}
