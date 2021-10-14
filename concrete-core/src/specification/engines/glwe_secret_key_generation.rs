use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::GlweSecretKeyEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

engine_error! {
    GlweSecretKeyGenerationError for GlweSecretKeyGenerationEngine @
    NullGlweDimension => "The secret key glwe dimension must be greater than zero.",
    NullPolynomialSize => "The secret key polynomial size must be greater than zero.",
    DegreeZeroPolynomial => "The secret key polynomial size must be greater than one. Otherwise\
                             you should prefer the lwe scheme."
}

/// A trait for engines generating glwe secret keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a fresh glwe secret key.
///
/// # Formal Definition
pub trait GlweSecretKeyGenerationEngine<SecretKey>: AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
{
    /// Generate a new glwe secret key.
    fn generate_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<SecretKey, GlweSecretKeyGenerationError<Self::EngineError>>;

    /// Unsafely generate a new glwe secret key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweSecretKeyGenerationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn generate_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> SecretKey;
}
