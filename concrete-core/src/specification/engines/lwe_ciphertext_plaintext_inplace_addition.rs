use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextPlaintextInplaceAdditionError for LweCiphertextPlaintextInplaceAdditionEngine @
    LweDimensionMismatch => "The input and output ciphertext lwe dimensions must be the same."
}

/// A trait for engines adding (inplace) plaintext to lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// addition of the `input_1` lwe ciphertext with the `input_2` plaintext.
///
/// # Formal Definition
pub trait LweCiphertextPlaintextInplaceAdditionEngine<InputCiphertext, Plaintext, OutputCiphertext>:
    AbstractEngine
where
    Plaintext: PlaintextEntity,
    InputCiphertext: LweCiphertextEntity<Representation = Plaintext::Representation>,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = Plaintext::Representation,
    >,
{
    /// Adds a plaintext to an lwe ciphertext.
    fn inplace_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Plaintext,
    ) -> Result<(), LweCiphertextPlaintextInplaceAdditionError<Self::EngineError>>;

    /// Unsafely adds a plaintext to an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextPlaintextInplaceAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input_1: &InputCiphertext,
        input_2: &Plaintext,
    );
}
