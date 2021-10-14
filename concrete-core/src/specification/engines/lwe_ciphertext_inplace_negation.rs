use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextInplaceNegationError for LweCiphertextInplaceNegationEngine @
    LweDimensionMismatch => "The input and output lwe dimension must be the same."
}

/// A trait for engines negating (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// negation of the `input` lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextInplaceNegationEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    /// Negates an lwe ciphertext.
    fn inplace_neg_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextInplaceNegationError<Self::EngineError>>;

    /// Unsafely negates an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceNegationError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_neg_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
