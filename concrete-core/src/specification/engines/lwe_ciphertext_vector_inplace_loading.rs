use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;
use concrete_commons::parameters::LweCiphertextRange;

engine_error! {
    LweCiphertextVectorInplaceLoadingError for LweCiphertextVectorInplaceLoadingEngine@
    LweDimensionMismatch => "The input and output lwe dimension must be the same.",
    DisorderedInputRange => "The input range bounds must be ordered.",
    OutOfVectorInputRange => "The input vector must contain the input range.",
    DisorderedOutputRange => "The output range bound must be ordered.",
    OutOfVectorOutputRange => "The output vector must contain the output range.",
    RangeSizeMismatch => "The input and output range must have the same size."
}

/// A trait for engines loading (inplace) a sub lwe ciphertext vector from another one.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills a piece of the `output_vector` lwe
/// ciphertext vector with a piece of the `input_vector` lwe ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceLoadingEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = InputCiphertextVector::KeyFlavor,
        Representation = InputCiphertextVector::Representation,
    >,
{
    /// Loads a subpart of an lwe ciphertext vector into another lwe ciphertext vector.
    fn inplace_load_lwe_ciphertext_vector(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), LweCiphertextVectorInplaceLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an lwe ciphertext vector into another lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceLoadingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_load_lwe_ciphertext_vector_unchecked(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    );
}
