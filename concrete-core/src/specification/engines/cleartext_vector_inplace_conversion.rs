use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextVectorEntity;

engine_error! {
    CleartextVectorInplaceConversionError for CleartextVectorInplaceConversionEngine @
    CleartextCountMismatch => "The input and output cleartext count must be the same"
}

/// A trait for engines converting (inplace) cleartexts vector.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` cleartext vector with the
/// conversion of the `input` cleartext vector to a different representation.
///
/// # Formal Definition
pub trait CleartextVectorInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextVectorEntity,
    Output: CleartextVectorEntity,
{
    /// Converts a cleartext vector inplace.
    fn inplace_convert_cleartext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), CleartextVectorInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextVectorInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_cleartext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
