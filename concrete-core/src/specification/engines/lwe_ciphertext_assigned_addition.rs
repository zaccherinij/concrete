use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextAssignedAdditionError for LweCiphertextAssignedAdditionEngine @
    LweDimensionMismatch => "The input and output lwe dimensions must be the same."
}

/// A trait for engines adding (assign) lwe ciphertexts.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation adds the `input` lwe ciphertext to the
/// `output` lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextAssignedAdditionEngine<InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    InputCiphertext: LweCiphertextEntity,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = InputCiphertext::KeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    /// Adds an lwe ciphertext to an other.
    fn assign_add_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    ) -> Result<(), LweCiphertextAssignedAdditionError<Self::EngineError>>;

    /// Unsafely add an lwe ciphertext to an other.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextAssignedAdditionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn assign_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
    );
}
