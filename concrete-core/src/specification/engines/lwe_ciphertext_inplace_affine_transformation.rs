use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity, PlaintextEntity,
};

engine_error! {
    LweCiphertextInplaceAffineTransformationError for LweCiphertextInplaceAffineTransformationEngine @
    LweDimensionMismatch => "The output and inputs lwe dimensions must be the same.",
    CleartextCountMismatch => "The cleartext vector count and inputs vector count must be the same."
}

/// A trait for engines performing (inplace) affine transformation of lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// result of the affine tranform of the `inputs` lwe ciphertext vector, with the `weights`
/// cleartext vector and the `bias` plaintext.
///
/// # Formal Definition
pub trait LweCiphertextInplaceAffineTransformationEngine<
    CiphertextVector,
    CleartextVector,
    Plaintext,
    OutputCiphertext,
>: AbstractEngine where
    OutputCiphertext: LweCiphertextEntity,
    CiphertextVector: LweCiphertextVectorEntity<
        Representation = OutputCiphertext::Representation,
        KeyFlavor = OutputCiphertext::KeyFlavor,
    >,
    CleartextVector: CleartextVectorEntity<Representation = OutputCiphertext::Representation>,
    Plaintext: PlaintextEntity<Representation = OutputCiphertext::Representation>,
{
    /// Performs the affine transform of an lwe ciphertext vector.
    fn inplace_affine_transform_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        inputs: &CiphertextVector,
        weights: &CleartextVector,
        bias: &Plaintext,
    ) -> Result<(), LweCiphertextInplaceAffineTransformationError<Self::EngineError>>;

    /// Unsafely performs the affine transform of an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceAffineTransformationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_affine_transform_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        inputs: &CiphertextVector,
        weights: &CleartextVector,
        bias: &Plaintext,
    );
}
