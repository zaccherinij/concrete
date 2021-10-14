use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweCiphertextVectorEntity};
use concrete_commons::parameters::LweCiphertextIndex;

engine_error! {
    LweCiphertextInplaceStoringError for LweCiphertextInplaceStoringEngine@
    LweDimensionMismatch => "The input and output lwe dimensions must be the same.",
    IndexTooLarge => "The index must not exceed the size of the vector."
}

/// A trait for engines storing (inplace) lwe ciphertexts in lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `i`th lwe ciphertext of the
/// `vector` lwe ciphertext vector, with the `ciphertext` lwe ciphertext.
///
/// # Formal Definition
pub trait LweCiphertextInplaceStoringEngine<Ciphertext, CiphertextVector>: AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
    Ciphertext: LweCiphertextEntity<
        KeyFlavor = CiphertextVector::KeyFlavor,
        Representation = CiphertextVector::Representation,
    >,
{
    /// Stores an lwe ciphertext in an lwe ciphertext vector.
    fn inplace_store_lwe_ciphertext(
        &mut self,
        vector: &mut CiphertextVector,
        ciphertext: &Ciphertext,
        i: LweCiphertextIndex,
    ) -> Result<(), LweCiphertextInplaceStoringError<Self::EngineError>>;

    /// Unsafely stores an lwe ciphertext in a lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceStoringError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_store_lwe_ciphertext_unchecked(
        &mut self,
        vector: &mut CiphertextVector,
        ciphertext: &Ciphertext,
        i: LweCiphertextIndex,
    );
}
