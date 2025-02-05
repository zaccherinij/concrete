use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextVectorEntity;

engine_error! {
    GlweCiphertextVectorDiscardingConversionError for GlweCiphertextVectorDiscardingConversionEngine @
    GlweDimensionMismatch => "The input and output GLWE dimension must be the same.",
    PolynomialSizeMismatch => "The input and output polynomial size must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

/// A trait for engines converting (discarding) GLWE ciphertext vectors .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` GLWE ciphertext vector
/// with the conversion of the `input` GLWE ciphertext vector to a type with a different
/// representation (for instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait GlweCiphertextVectorDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextVectorEntity,
    Output: GlweCiphertextVectorEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a GLWE ciphertext vector .
    fn discard_convert_glwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), GlweCiphertextVectorDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a GLWE ciphertext vector .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorDiscardingConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
