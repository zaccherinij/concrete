use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextInplaceConversionError for PlaintextInplaceConversionEngine @
}

/// A trait for engines converting (inplace) plaintexts .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext with the
/// conversion of the `input` plaintext to a different representation.
///
/// # Formal Definition
pub trait PlaintextInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextEntity,
    Output: PlaintextEntity,
{
    /// Converts a plaintext inplace.
    fn inplace_convert_plaintext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), PlaintextInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextInplaceConversionError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn inplace_convert_plaintext_unchecked(&mut self, output: &mut Output, input: &Input);
}
