use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweCiphertextVectorEntity;
use concrete_commons::parameters::LweCiphertextRange;

engine_error! {
    LweCiphertextVectorDiscardingLoadingError for LweCiphertextVectorDiscardingLoadingEngine @
    LweDimensionMismatch => "The input and output LWE dimension must be the same.",
    UnorderedInputRange => "The input range bounds must be ordered.",
    OutOfVectorInputRange => "The input vector must contain the input range.",
    UnorderedOutputRange => "The output range bound must be ordered.",
    OutOfVectorOutputRange => "The output vector must contain the output range.",
    RangeSizeMismatch => "The input and output range must have the same size."
}

/// A trait for engines loading (discarding) a sub LWE ciphertext vector from another one.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills a piece of the `output_vector` lwe
/// ciphertext vector with a piece of the `input_vector` LWE ciphertext vector.
///
/// # Formal Definition
pub trait LweCiphertextVectorDiscardingLoadingEngine<InputCiphertextVector, OutputCiphertextVector>:
    AbstractEngine
where
    InputCiphertextVector: LweCiphertextVectorEntity,
    OutputCiphertextVector: LweCiphertextVectorEntity<KeyFlavor = InputCiphertextVector::KeyFlavor>,
{
    /// Loads a subpart of an LWE ciphertext vector into another LWE ciphertext vector.
    fn discard_load_lwe_ciphertext_vector(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    ) -> Result<(), LweCiphertextVectorDiscardingLoadingError<Self::EngineError>>;

    /// Unsafely loads a subpart of an LWE ciphertext vector into another LWE ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorDiscardingLoadingError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn discard_load_lwe_ciphertext_vector_unchecked(
        &mut self,
        output_vector: &mut OutputCiphertextVector,
        input_vector: &InputCiphertextVector,
        output_range: LweCiphertextRange,
        input_range: LweCiphertextRange,
    );
}
