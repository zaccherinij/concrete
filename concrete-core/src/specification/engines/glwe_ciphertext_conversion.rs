use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweCiphertextEntity;

engine_error! {
    GlweCiphertextConversionError for GlweCiphertextConversionEngine @
}

/// A trait for engines converting glwe ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a glwe ciphertext containing the
/// conversion of the `input` glwe ciphertext to a different representation.
///
/// # Formal Definition
pub trait GlweCiphertextConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweCiphertextEntity,
    Output: GlweCiphertextEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a glwe ciphertext.
    fn convert_glwe_ciphertext(
        &mut self,
        input: &Input,
    ) -> Result<Output, GlweCiphertextConversionError<Self::EngineError>>;

    /// Unsafely converts a glwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_glwe_ciphertext_unchecked(&mut self, input: &Input) -> Output;
}
