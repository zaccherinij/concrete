use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{CleartextEntity, LweCiphertextEntity};

engine_error! {
    LweCiphertextCleartextAssignedMultiplicationError for LweCiphertextCleartextAssignedMultiplicationEngine @
}

/// A trait for engines multiplying (assign) lwe ciphertexts by cleartexts.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation multiply the `output` lwe ciphertext with
/// the `input` cleartext.
///
/// # Formal Definition
pub trait LweCiphertextCleartextAssignedMultiplicationEngine<Ciphertext, Cleartext>:
    AbstractEngine
where
    Cleartext: CleartextEntity,
    Ciphertext: LweCiphertextEntity<Representation = Cleartext::Representation>,
{
    /// Multiply an lwe ciphertext with a cleartext.
    fn assign_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    ) -> Result<(), LweCiphertextCleartextAssignedMultiplicationError<Self::EngineError>>;

    /// Unsafely multiply an lwe ciphertext with a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextCleartextAssignedMultiplicationError`]. For safety concerns _specific_ to
    /// an engine, refer to the implementer safety section.
    unsafe fn assign_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut Ciphertext,
        input: &Cleartext,
    );
}
