use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextInplaceAdditionError for LweCiphertextInplaceAdditionEngine @
    LweDimensionMismatch => "All the ciphertext lwe dimensions must be the same."
}

/// A trait for engines adding (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// addition of the `input_1` lwe ciphertext and the `input_2` lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextInplaceAdditionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    /// Adds two lwe ciphertexts.
    fn inplace_add_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    ) -> Result<(), LweCiphertextInplaceAdditionError<Self::EngineError>>;

    /// Unsafely adds two lwe ciphertexts.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceAdditionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &InputCiphertext,
    );
}
