use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyInplaceConversionError for LweKeyswitchKeyInplaceConversionEngine @
    LweDimensionMismatch => "The two keys must have the same lwe dimension.",
    DecompositionBaseLogMismatch => "The two keys must have the same base logarithms.",
    DecompositionLevelCountMismatch => "The two keys must have the same level counts."
}

/// A trait for engines converting (inplace) lwe keyswitch keys .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe keyswitch key with
/// the conversion of the `input` lwe keyswitch key to a different representation.
///
/// # Formal Definition
pub trait LweKeyswitchKeyInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweKeyswitchKeyEntity,
    Output: LweKeyswitchKeyEntity<
        InputKeyFlavor = Input::InputKeyFlavor,
        OutputKeyFlavor = Input::OutputKeyFlavor,
    >,
{
    /// Converts a lwe keyswitch key inplace.
    fn inplace_convert_lwe_keyswitch_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweKeyswitchKeyInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe keyswitch key inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_lwe_keyswitch_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
