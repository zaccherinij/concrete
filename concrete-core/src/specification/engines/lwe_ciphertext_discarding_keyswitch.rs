use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweCiphertextEntity, LweKeyswitchKeyEntity};

engine_error! {
    LweCiphertextDiscardingKeyswitchError for LweCiphertextDiscardingKeyswitchEngine @
    InputLweDimensionMismatch => "The input ciphertext LWE dimension and keyswitch key input LWE \
                                  dimensions must be the same.",
    OutputLweDimensionMismatch => "The output ciphertext LWE dimension and keyswitch output LWE \
                                   dimensions must be the same."
}

/// A trait for engines keyswitching (discarding) LWE ciphertexts.
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE ciphertext with the
/// keyswitch of the `input` LWE ciphertext, using the `ksk` LWE keyswitch key.
///
/// # Formal Definition
pub trait LweCiphertextDiscardingKeyswitchEngine<KeyswitchKey, InputCiphertext, OutputCiphertext>:
    AbstractEngine
where
    KeyswitchKey: LweKeyswitchKeyEntity,
    InputCiphertext: LweCiphertextEntity<KeyFlavor = KeyswitchKey::InputKeyFlavor>,
    OutputCiphertext: LweCiphertextEntity<KeyFlavor = KeyswitchKey::OutputKeyFlavor>,
{
    /// Keyswitch an LWE ciphertext.
    fn discard_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    ) -> Result<(), LweCiphertextDiscardingKeyswitchError<Self::EngineError>>;

    /// Unsafely keyswitch an LWE ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextDiscardingKeyswitchError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut OutputCiphertext,
        input: &InputCiphertext,
        ksk: &KeyswitchKey,
    );
}
