use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextEntity;

engine_error! {
    CleartextInplaceConversionError for CleartextInplaceConversionEngine @
}

/// A trait for engines converting (inplace) cleartexts .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` cleartext with the
/// conversion of the `input` cleartext to a different representation.
///
/// # Formal Definition
pub trait CleartextInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: CleartextEntity,
    Output: CleartextEntity,
{
    /// Converts a cleartext inplace.
    fn inplace_convert_cleartext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), CleartextInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a cleartext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextInplaceConversionError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn inplace_convert_cleartext_unchecked(&mut self, output: &mut Output, input: &Input);
}
