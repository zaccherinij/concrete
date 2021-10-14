use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextInplaceConversionError for LweCiphertextInplaceConversionEngine @
    LweDimensionMismatch => "All the ciphertext lwe dimensions must be the same."
}

/// A trait for engines converting (inplace) lwe ciphertexts .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// conversion of the `input` lwe ciphertext to a different representation.
///
/// # Formal Definition
pub trait LweCiphertextInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextEntity,
    Output: LweCiphertextEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a lwe ciphertext inplace.
    fn inplace_convert_lwe_ciphertext(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCiphertextInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe ciphertext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
