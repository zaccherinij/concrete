use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweCiphertextVectorEntity};
use concrete_commons::parameters::LweCiphertextIndex;

engine_error! {
    LweCiphertextDiscardingLoadingError for LweCiphertextDiscardingLoadingEngine @
    LweDimensionMismatch => "The output and input LWE dimension must be the same.",
    IndexTooLarge => "The index must not exceed the size of the vector."
}

/// A trait for engines loading (discarding) an LWE ciphertext from a LWE ciphertext vector.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `ciphertext` LWE ciphertext with
/// the `i`th LWE ciphertext of the `vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingLoadingEngine<CiphertextVector, Ciphertext>:
    AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity<KeyFlavor = Ciphertext::KeyFlavor>,
{
    /// Loads an LWE ciphertext from an LWE ciphertext vector.
    fn discard_load_lwe_ciphertext(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<(), LweCiphertextDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads an LWE ciphertext from an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_unchecked(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    );
}
