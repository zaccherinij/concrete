use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextConversionError for LweCiphertextConversionEngine @
}

/// A trait for engines converting lwe ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a lwe ciphertext containing the
/// conversion of the `input` lwe ciphertext to a different representation.
///
/// # Formal Definition
pub trait LweCiphertextConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextEntity,
    Output: LweCiphertextEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a lwe ciphertext.
    fn convert_lwe_ciphertext(
        &mut self,
        input: &Input,
    ) -> Result<Output, LweCiphertextConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_lwe_ciphertext_unchecked(&mut self, input: &Input) -> Output;
}
