use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweBootstrapKeyEntity;

engine_error! {
    LweBootstrapKeyInplaceConversionError for LweBootstrapKeyInplaceConversionEngine @
    LweDimensionMismatch => "The two keys must have the same lwe dimension.",
    GlweDimensionMismatch => "The two keys must have the same glwe dimension.",
    PolynomialSizeMismatch => "The two keys must have the same polynomial size.",
    DecompositionBaseLogMismatch => "The two keys must have the same base logarithms.",
    DecompositionLevelCountMismatch => "The two keys must have the same level counts."
}

/// A trait for engines converting (inplace) lwe bootstrap keys .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe bootstrap key with
/// the conversion of the `input` lwe bootstrap key to a different representation.
///
/// # Formal Definition
pub trait LweBootstrapKeyInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweBootstrapKeyEntity,
    Output: LweBootstrapKeyEntity<
        InputKeyFlavor = Input::InputKeyFlavor,
        OutputKeyFlavor = Input::OutputKeyFlavor,
    >,
{
    /// Converts a lwe bootstrap key inplace.
    fn inplace_convert_lwe_bootstrap_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweBootstrapKeyInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe bootstrap key inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_lwe_bootstrap_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
