use concrete_commons::parameters::LweDimension;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweSecretKey32, LweSecretKey64};
use crate::backends::core::private::crypto::secret::LweSecretKey as ImplLweSecretKey;
use crate::specification::engines::{LweSecretKeyGenerationEngine, LweSecretKeyGenerationError};

impl LweSecretKeyGenerationEngine<LweSecretKey32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_secret_key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// engine.destroy(lwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey32, LweSecretKeyGenerationError<Self::EngineError>> {
        Ok(unsafe { self.generate_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn generate_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey32 {
        LweSecretKey32(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}

impl LweSecretKeyGenerationEngine<LweSecretKey64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// let lwe_secret_key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// assert_eq!(lwe_secret_key.lwe_dimension(), lwe_dimension);
    /// engine.destroy(lwe_secret_key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn generate_lwe_secret_key(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> Result<LweSecretKey64, LweSecretKeyGenerationError<Self::EngineError>> {
        Ok(unsafe { self.generate_lwe_secret_key_unchecked(lwe_dimension) })
    }

    unsafe fn generate_lwe_secret_key_unchecked(
        &mut self,
        lwe_dimension: LweDimension,
    ) -> LweSecretKey64 {
        LweSecretKey64(ImplLweSecretKey::generate_binary(
            lwe_dimension,
            &mut self.secret_generator,
        ))
    }
}
