use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{
    GlweCiphertextVectorEntity, LweBootstrapKeyEntity, LweCiphertextVectorEntity,
};

engine_error! {
    LweCiphertextVectorInplaceBootstrapError for LweCiphertextVectorInplaceBootstrapEngine @
    InputLweDimensionMismatch => "The input vector and key input lwe dimension must be the same.",
    OutputLweDimensionMismatch => "The output vector and key output lwe dimension must be the same.",
    AccumulatorGlweDimensionMismatch => "The accumulator vector and key glwe dimension must be the same.",
    AccumulatorPolynomialSizeMismatch => "The accumulator vector and key polynomial size must be the same.",
    CiphertextCountMismatch => "The input and output ciphertext count must be the same."
}

/// A trait for engines bootstrapping (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the element-wise bootstrap of the `input` lwe ciphertext vector, using the `acc`
/// accumulator as lookup-table, and the `bsk` bootstrap key.
///
/// # Formal Definition
// Todo: Ideally, the bsk representation should be same as ciphertext.
pub trait LweCiphertextVectorInplaceBootstrapEngine<
    BootstrapKey,
    AccumulatorVector,
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    AccumulatorVector: GlweCiphertextVectorEntity<KeyFlavor = BootstrapKey::OutputKeyFlavor>,
    InputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = BootstrapKey::InputKeyFlavor,
        Representation = AccumulatorVector::Representation,
    >,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = BootstrapKey::OutputKeyFlavor,
        Representation = AccumulatorVector::Representation,
    >,
{
    /// Bootstraps an lwe ciphertext vector.
    fn inplace_bootstrap_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        acc: &AccumulatorVector,
        bsk: &BootstrapKey,
    ) -> Result<(), LweCiphertextVectorInplaceBootstrapError<Self::EngineError>>;

    /// Unsafely bootstraps an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceBootstrapError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_bootstrap_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        acc: &AccumulatorVector,
        bsk: &BootstrapKey,
    );
}
