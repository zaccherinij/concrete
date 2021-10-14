use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyConversionError for LweBootstrapKeyConversionEngine @
}

/// A trait for engines converting lwe bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a lwe bootstrap key containing the
/// conversion of the `input` key to a different representation.
///
/// # Formal Definition
pub trait LweBootstrapKeyConversionEngine<InputKey, OutputKey>: AbstractEngine
where
    InputKey: LweBootstrapKeyEntity,
    OutputKey: LweBootstrapKeyEntity<
        InputKeyFlavor = InputKey::InputKeyFlavor,
        OutputKeyFlavor = InputKey::OutputKeyFlavor,
    >,
{
    /// Converts an lwe bootstrap key.
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &InputKey,
    ) -> Result<OutputKey, LweBootstrapKeyConversionError<Self::EngineError>>;

    /// Unsafely converts an lwe bootstrap key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyConversionError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &InputKey) -> OutputKey;
}
