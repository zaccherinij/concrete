use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweSecretKey32, GlweSecretKey64};
use crate::backends::core::private::crypto::secret::GlweSecretKey as ImplGlweSecretKey;
use crate::specification::engines::{GlweSecretKeyGenerationEngine, GlweSecretKeyGenerationError};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

impl GlweSecretKeyGenerationEngine<GlweSecretKey32> for CoreEngine {
    fn generate_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey32, GlweSecretKeyGenerationError<Self::EngineError>> {
        Ok(unsafe { self.generate_glwe_secret_key_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn generate_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey32 {
        GlweSecretKey32(ImplGlweSecretKey::generate_binary(
            glwe_dimension,
            polynomial_size,
            &mut self.secret_generator,
        ))
    }
}

impl GlweSecretKeyGenerationEngine<GlweSecretKey64> for CoreEngine {
    fn generate_glwe_secret_key(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> Result<GlweSecretKey64, GlweSecretKeyGenerationError<Self::EngineError>> {
        Ok(unsafe { self.generate_glwe_secret_key_unchecked(glwe_dimension, polynomial_size) })
    }

    unsafe fn generate_glwe_secret_key_unchecked(
        &mut self,
        glwe_dimension: GlweDimension,
        polynomial_size: PolynomialSize,
    ) -> GlweSecretKey64 {
        GlweSecretKey64(ImplGlweSecretKey::generate_binary(
            glwe_dimension,
            polynomial_size,
            &mut self.secret_generator,
        ))
    }
}
