use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorInplaceConversionError for LweCiphertextVectorInplaceConversionEngine @
    LweDimensionMismatch => "The input and output lwe dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphretext count must be the same."
}

/// A trait for engines converting (inplace) lwe ciphertext vectors .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the conversion of the `input` lwe ciphertext vector to a different representation.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextVectorEntity,
    Output: LweCiphertextVectorEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a lwe ciphertext vector inplace.
    fn inplace_convert_lwe_ciphertext_vector(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweCiphertextVectorInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe ciphertext vector inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceConversionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_convert_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
