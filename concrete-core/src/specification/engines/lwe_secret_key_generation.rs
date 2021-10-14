use crate::specification::engines::AbstractEngine;
use crate::specification::entities::LweSecretKeyEntity;
use concrete_commons::parameters::LweDimension;

engine_error! {
    LweSecretKeyGenerationError for LweSecretKeyGenerationEngine @
    NullLweDimension => "The lwe dimension must be greater than zero."
}

/// A trait for engines generating lwe secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a fresh lwe secret key.
///
/// # Formal Definition
pub trait LweSecretKeyGenerationEngine<SecretKey>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
{
    /// Generates an lwe secret key.
    fn generate_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<SecretKey, LweSecretKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates an lwe secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweSecretKeyGenerationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn generate_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> SecretKey;
}
