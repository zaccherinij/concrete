use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextEntity;

engine_error! {
    LweCiphertextAssignedNegationError for LweCiphertextAssignedNegationEngine @
}

/// A trait for engines negating (assign) lwe ciphertexts.
///
/// # Semantics
///
/// This [assigned](super#operation-semantics) operation negates the `input` lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextAssignedNegationEngine<Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
{
    /// Negates an lwe ciphertext.
    fn assigned_neg_lwe_ciphertext(
        &mut self,
        input: &mut Ciphertext,
    ) -> Result<(), LweCiphertextAssignedNegationError<Self::EngineError>>;

    /// Unsafely negates an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextAssignedNegationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn assigned_neg_lwe_ciphertext_unchecked(&mut self, input: &mut Ciphertext);
}
