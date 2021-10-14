use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextInplaceConversionError for GlweCiphertextInplaceConversionEngine @
    GlweDimensionMismatch => "The input and output glwe dimension must be the same.",
    PolynomialSizeMismatch => "The input and output polynomial size must be the same."
}

/// A trait for engines converting (inplace) glwe ciphertexts .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` glwe ciphertext with the
/// conversion of the `input` glwe ciphertext to a different representation.
///
/// # Formal Definition
pub trait GlweCiphertextInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextEntity,
    Output: GlweCiphertextEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a glwe ciphertext inplace.
    fn inplace_convert_glwe_ciphertext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), GlweCiphertextInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a glwe ciphertext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_glwe_ciphertext_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
