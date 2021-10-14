use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;

engine_error! {
    LweCiphertextVectorConversionError for LweCiphertextVectorConversionEngine @
}

/// A trait for engines converting lwe ciphertext vectors.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a lwe ciphertext vector containing
/// the conversion of the `input` lwe ciphertext vector to a different representation.
///
/// # Formal Definition
pub trait LweCiphertextVectorConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweCiphertextVectorEntity,
    Output: LweCiphertextVectorEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a lwe ciphertext vector.
    fn convert_lwe_ciphertext_vector(
        &mut self,
        input: &Input,
    ) -> Result<Output, LweCiphertextVectorConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn convert_lwe_ciphertext_vector_unchecked(&mut self, input: &Input) -> Output;
}
