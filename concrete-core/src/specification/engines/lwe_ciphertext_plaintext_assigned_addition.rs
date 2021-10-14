use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, PlaintextEntity};

engine_error! {
    LweCiphertextPlaintextAssignedAdditionError for LweCiphertextPlaintextAssignedAdditionEngine @
}

/// A trait for engines adding (assign) plaintexts to lwe ciphertexts.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation adds the `input` plaintext to the `output`
/// lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextPlaintextAssignedAdditionEngine<Ciphertext, Plaintext>:
    AbstractEngine
where
    Plaintext: PlaintextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Plaintext::Representation>,
{
    /// Add a plaintext to an lwe ciphertext.
    fn assigned_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    ) -> Result<(), LweCiphertextPlaintextAssignedAdditionError<Self::EngineError>>;

    /// Unsafely add a plaintext to an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextPlaintextAssignedAdditionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn assigned_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Plaintext,
    );
}
