use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextCleartextInplaceMultiplicationError for LweCiphertextCleartextInplaceMultiplicationEngine @
    LweDimensionMismatch => "The input and output ciphertext lwe dimension must be the same."
}

/// A trait for engines multiplying (inplace) lwe ciphertext by cleartexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// multiplication of the `input_1` lwe ciphertext with the `input_2` cleartext.
///
/// # Formal Definition
pub trait LweCiphertextCleartextInplaceMultiplicationEngine<
    InputCiphertext,
    Cleartext,
    OutputCiphertext,
>: AbstractEngine where
    Cleartext: CleartextEntity,
    InputCiphertext: LweCiphertextEntity<Representation = Cleartext::Representation>,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = Cleartext::Representation,
    >,
{
    /// Multiply an lwe ciphertext with a cleartext.
    fn inplace_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Cleartext,
    ) -> Result<(), LweCiphertextCleartextInplaceMultiplicationError<Self::EngineError>>;

    /// Unsafely multiply an lwe ciphertext with a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextCleartextInplaceMultiplicationError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.
    unsafe fn inplace_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Cleartext,
    );
}
