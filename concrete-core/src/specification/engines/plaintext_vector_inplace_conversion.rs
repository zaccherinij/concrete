use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextVectorEntity;

engine_error! {
    PlaintextVectorInplaceConversionError for PlaintextVectorInplaceConversionEngine @
    PlaintextCountMismatch => "The input and output plaintext count must be the same"
}

/// A trait for engines converting (inplace) plaintext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext vector with the
/// conversion of the `input` plaintext vector to a different representation.
///
/// # Formal Definition
pub trait PlaintextVectorInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: PlaintextVectorEntity,
    Output: PlaintextVectorEntity,
{
    /// Converts a plaintext vector inplace.
    fn inplace_convert_plaintext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), PlaintextVectorInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a plaintext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextVectorInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_plaintext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
