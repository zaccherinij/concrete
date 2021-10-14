use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweCiphertextEntity, LweKeyswitchKeyEntity};

engine_error! {
    LweCiphertextInplaceKeyswitchError for LweCiphertextInplaceKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext lwe dimension and keyswitch key input lwe \
                                  dimensions must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext lwe dimension and keyswitch output lwe \
                                   dimensions must be the same."
}

/// A trait for engines keyswitching (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// keyswitch of the `input` lwe ciphertext, using the `ksk` lwe keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextInplaceKeyswitchEngine<KeyswitchKey, InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity<KeyFlavor = KeyswitchKey::InputKeyFlavor>,
    OutputCiphertext: LweCiphertextEntity<
        KeyFlavor = KeyswitchKey::OutputKeyFlavor,
        Representation = InputCiphertext::Representation,
    >,
{
    /// Keyswitch an lwe ciphertext.
    fn inplace_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextInplaceKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceKeyswitchError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    );
}
