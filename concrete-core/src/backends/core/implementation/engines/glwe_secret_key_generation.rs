use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{GlweSecretKey32, GlweSecretKey64};
use crate::backends::core::private::crypto::secret::GlweSecretKey as ImplGlweSecretKey;
use crate::specification::engines::{GlweSecretKeyGenerationEngine, GlweSecretKeyGenerationError};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

impl GlweSecretKeyGenerationEngine<GlweSecretKey32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let glwe_secret_key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     ?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    /// engine.destroy(glwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
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
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// let glwe_secret_key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     ?;
    /// assert_eq!(glwe_secret_key.glwe_dimension(), glwe_dimension);
    /// assert_eq!(glwe_secret_key.polynomial_size(), polynomial_size);
    /// engine.destroy(glwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
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
