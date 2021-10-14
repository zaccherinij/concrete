use super::engine_error;
use crate::specification::engines::AbstractEngine;

use crate::specification::entities::{LweKeyswitchKeyEntity, LweSecretKeyEntity};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

engine_error! {
    LweKeyswitchKeyGenerationError for LweKeyswitchKeyGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

/// A trait for engines generating lwe keyswitch keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an lwe keyswitch key allowing to
/// switch from the `input_key` lwe secret key to the `output_key` lwe secret key.
///
/// # Formal Definition
pub trait LweKeyswitchKeyGenerationEngine<InputSecretKey, OutputSecretKey, KeyswitchKey>:
    AbstractEngine
where
    InputSecretKey: LweSecretKeyEntity,
    OutputSecretKey: LweSecretKeyEntity<Representation = InputSecretKey::Representation>,
    KeyswitchKey: LweKeyswitchKeyEntity<
        InputKeyFlavor = InputSecretKey::KeyFlavor,
        OutputKeyFlavor = OutputSecretKey::KeyFlavor,
    >,
{
    /// Generates an lwe keyswitch key.
    fn generate_lwe_keyswitch_key(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> Result<KeyswitchKey, LweKeyswitchKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates an lwe keyswitch key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyGenerationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn generate_lwe_keyswitch_key_unchecked(
        &mut self,
        input_key: &InputSecretKey,
        output_key: &OutputSecretKey,
        decomposition_level_count: DecompositionLevelCount,
        decomposition_base_log: DecompositionBaseLog,
        noise: Variance,
    ) -> KeyswitchKey;
}
