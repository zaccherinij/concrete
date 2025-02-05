use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;
use concrete_commons::parameters::LweCiphertextRange;

engine_error! {
    LweCiphertextVectorLoadingError for LweCiphertextVectorLoadingEngine @
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfVectorInputRange => "The input vector must contain the input range."
}

/// A trait for engines loading a sub LWE ciphertext vector from another one.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an LWE ciphertext vector containing
/// a piece of the `vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorLoadingEngine<CiphertextVector, SubCiphertextVector>:
    AbstractEngine
where
    CiphertextVector: LweCiphertextVectorEntity,
    SubCiphertextVector: LweCiphertextVectorEntity<KeyFlavor = CiphertextVector::KeyFlavor>,
{
    /// Loads a subpart of an LWE ciphertext vector.
    fn load_lwe_ciphertext_vector(
        &mut self,
        vector: &CiphertextVector,
        range: LweCiphertextRange,
    ) -> Result<SubCiphertextVector, LweCiphertextVectorLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorLoadingError`]. For safety concerns _specific_ to an engine, refer
    /// to the implementer safety section.
    unsafe fn load_lwe_ciphertext_vector_unchecked(
        &mut self,
        vector: &CiphertextVector,
        range: LweCiphertextRange,
    ) -> SubCiphertextVector;
}
