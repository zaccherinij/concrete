use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;

engine_error! {
    GlweSecretKeyInplaceConversionError for GlweSecretKeyInplaceConversionEngine @
    GlweDimensionMismatch => "The input and output glwe dimension must be the same.",
    PolynomialSizeMismatch => "The input and output polynomial size must be the same."
}

/// A trait for engines converting (inplace) glwe secret keys .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` glwe secret key with the
/// conversion of the `input` glwe secret key to a different representation.
///
/// # Formal Definition
pub trait GlweSecretKeyInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: GlweSecretKeyEntity,
    Output: GlweSecretKeyEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a glwe secret key inplace.
    fn inplace_convert_glwe_secret_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), GlweSecretKeyInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a glwe secret key inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSecretKeyInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_glwe_secret_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
