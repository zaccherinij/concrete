use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweCiphertextVectorEntity, LweKeyswitchKeyEntity};

engine_error! {
    LweCiphertextVectorInplaceKeyswitchError for LweCiphertextVectorInplaceKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext vector and keyswitch key input lwe \
                                  dimension must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext vector and keyswitch key output lwe \
                                   dimension must be the same.",
    CiphertextCountMismatch => "The input and output ciphertexts have different ciphertext counts."
}

/// A trait for engines keyswitching (inplace) lwe ciphertext vectors.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext vector
/// with the element-wise keyswitch of the `input` lwe ciphertext vector, under the `ksk` lwe
/// keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextVectorInplaceKeyswitchEngine<
    KeyswitchKey,
    InputCiphertextVector,
    OutputCiphertextVector,
>: AbstractEngine where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertextVector: LweCiphertextVectorEntity<KeyFlavor = KeyswitchKey::InputKeyFlavor>,
    OutputCiphertextVector: LweCiphertextVectorEntity<
        KeyFlavor = KeyswitchKey::OutputKeyFlavor,
        Representation = InputCiphertextVector::Representation,
    >,
{
    /// Keyswitch an lwe ciphertext vector.
    fn inplace_keyswitch_lwe_ciphertext_vector(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextVectorInplaceKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an lwe ciphertext vector.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextVectorInplaceKeyswitchError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn inplace_keyswitch_lwe_ciphertext_vector_unchecked(
        &mut self,
        output: &mut OutputCiphertextVector,
        input: &InputCiphertextVector,
        ksk: &KeyswitchKey,
    );
}
