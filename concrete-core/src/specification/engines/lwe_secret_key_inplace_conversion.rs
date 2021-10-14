use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweSecretKeyEntity;

engine_error! {
    LweSecretKeyInplaceConversionError for LweSecretKeyInplaceConversionEngine @
    LweDimensionMismatch => "The input and output lwe dimension must be the same."
}

/// A trait for engines converting (inplace) lwe secret keys .
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe secret key with the
/// conversion of the `input` lwe secret key to a different representation.
///
/// # Formal Definition
pub trait LweSecretKeyInplaceConversionEngine<Input, Output>: AbstractEngine
where
    Input: LweSecretKeyEntity,
    Output: LweSecretKeyEntity<KeyFlavor = Input::KeyFlavor>,
{
    /// Converts a lwe secret key inplace.
    fn inplace_convert_lwe_secret_key(
        &mut self,
        output: &mut Output,
        input: &Input,
    ) -> Result<(), LweSecretKeyInplaceConversionError<Self::EngineError>>;

    /// Unsafely converts a lwe secret key inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSecretKeyInplaceConversionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_convert_lwe_secret_key_unchecked(
        &mut self,
        output: &mut Output,
        input: &Input,
    );
}
