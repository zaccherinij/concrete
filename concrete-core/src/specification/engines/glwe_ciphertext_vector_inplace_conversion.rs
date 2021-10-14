use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextVectorEntity;

engine_error! {
    GlweCiphertextVectorInplaceConversionError for GlweCiphertextVectorInplaceConversionEngine @
    GlweDimensionMismatch => "The input and output glwe dimension must be the same.",
    PolynomialSizeMismatch => "The input and output polynomial size must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

/// A trait for engines converting (inplace) glwe ciphertext vectors .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` glwe ciphertext vector
/// with the conversion of the `input` glwe ciphertext vector to a different representation.
///
/// # Formal Definition
pub trait GlweCiphertextVectorInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextVectorEntity,
    Output: GlweCiphertextVectorEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a glwe ciphertext vector inplace.
    fn inplace_convert_glwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), GlweCiphertextVectorInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a glwe ciphertext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextVectorInplaceConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_convert_glwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
