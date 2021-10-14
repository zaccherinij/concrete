use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

engine_error! {
    LweCiphertextInplaceBootstrapError for LweCiphertextInplaceBootstrapEngine @
    InputLweDimensionMismatch => "The input ciphertext and key lwe dimensions must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext and key lwe dimensions must be the same.",
    AccumulatorPolynomialSizeMismatch => "The accumulator and key polynomial sizes must be the same.",
    AccumulatorGlweDimensionMismatch => "The accumulator and key glwe dimensions must be the same."
}

/// A trait for engines bootstrapping (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// bootstrap of the `input` lwe ciphertext, using the `acc` accumulator as lookup-table, and the
/// `bsk` bootstrap key.
///
/// # Formal Definition
// Todo: Ideally, the bsk representation should be same as ciphertext.
pub trait LweCiphertextInplaceBootstrapEngine<
    BootstrapKey,
    Accumulator,
    InputCiphertext,
    OutputCiphertext,
>: AbstractEngine where
    BootstrapKey: LweBootstrapKeyEntity,
    Accumulator: GlweCiphertextEntity<KeyFlavor = BootstrapKey::OutputKeyFlavor>,
    InputCiphertext: LweCiphertextEntity<
        KeyFlavor = BootstrapKey::InputKeyFlavor,
        Representation = Accumulator::Representation,
    >,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = BootstrapKey::OutputKeyFlavor,
        Representation = Accumulator::Representation,
    >,
{
    /// Bootstrap an lwe ciphertext inplace.
    fn inplace_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    ) -> Result<(), LweCiphertextInplaceBootstrapError<Self::EngineError>>;

    /// Unsafely bootstrap an lwe ciphertext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceBootstrapError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        acc: &Accumulator,
        bsk: &BootstrapKey,
    );
}
