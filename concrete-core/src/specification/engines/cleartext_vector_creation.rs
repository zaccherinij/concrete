use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorCreationError for CleartextVectorCreationEngine @
    EmptyInput => "The input slice must not be empty."
}

/// A trait for engines creating cleartext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext vector from the `raw`
/// slice of raw values.
///
/// # Formal Definition
pub trait CleartextVectorCreationEngine<Raw, CleartextVector>: AbstractEngine
where
    CleartextVector: CleartextVectorEntity,
{
    /// Creates a cleartext vector from a slice of raw values.
    fn create_cleartext_vector(
        &mut self,
        raw: &[Raw],
    ) -> Result<CleartextVector, CleartextVectorCreationError<Self::EngineError>>;

    /// Unsafely creates a cleartext vector from a slice of raw values.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorCreationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn create_cleartext_vector_unchecked(&mut self, raw: &[Raw]) -> CleartextVector;
}
