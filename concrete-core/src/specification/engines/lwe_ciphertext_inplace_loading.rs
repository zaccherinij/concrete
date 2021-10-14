use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweCiphertextVectorEntity};
use concrete_commons::parameters::LweCiphertextIndex;

engine_error! {
    LweCiphertextInplaceLoadingError for LweCiphertextInplaceLoadingEngine@
    LweDimensionMismatch => "The output and input lwe dimension must be the same.",
    IndexTooLarge => "The index must not exceed the size of the vector."
}

/// A trait for engines loading (inplace) an lwe ciphertext from a lwe ciphertext vector.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `ciphertext` lwe ciphertext with
/// the `i`th lwe ciphertext of the `vector` lwe ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextInplaceLoadingEngine<CiphertextVector, Ciphertext>: AbstractEngine
where
    Ciphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = Ciphertext::KeyFlavor,
        Representation = Ciphertext::Representation,
    >,
{
    /// Loads an lwe ciphertext from an lwe ciphertext vector.
    fn inplace_load_lwe_ciphertext(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    ) -> Result<(), LweCiphertextInplaceLoadingError<Self::EngineError>>;

    /// Unsafely loads an lwe ciphertext from an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceLoadingError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_load_lwe_ciphertext_unchecked(
        &mut self,
        ciphertext: &mut Ciphertext,
        vector: &CiphertextVector,
        i: LweCiphertextIndex,
    );
}
