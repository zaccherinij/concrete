use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweKeyswitchKeyEntity;

engine_error! {
    LweKeyswitchKeyDiscardingConversionError for LweKeyswitchKeyDiscardingConversionEngine @
    InputLweDimensionMismatch => "The two keys must have the same input LWE dimension.",
    OutputLweDimensionMismatch => "The two keys must have the same output LWE dimension.",
    DecompositionBaseLogMismatch => "The two keys must have the same base logarithms.",
    DecompositionLevelCountMismatch => "The two keys must have the same level counts."
}

/// A trait for engines converting (discarding) LWE keyswitch keys .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `output` LWE keyswitch key with
/// the conversion of the `input` LWE keyswitch key to a type with a different representation (for
/// instance from cpu to gpu memory).
///
/// # Formal Definition
pub trait LweKeyswitchKeyDiscardingConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweKeyswitchKeyEntity,
    Output: LweKeyswitchKeyEntity<
        InputKeyFlavor = Input::InputKeyFlavor,
        OutputKeyFlavor = Input::OutputKeyFlavor,
    >,
{
    /// Converts a LWE keyswitch key .
    fn discard_convert_lwe_keyswitch_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweKeyswitchKeyDiscardingConversionError<Self::EngineError>>;

    /// Unsafely converts a LWE keyswitch key .
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweKeyswitchKeyDiscardingConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn discard_convert_lwe_keyswitch_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
