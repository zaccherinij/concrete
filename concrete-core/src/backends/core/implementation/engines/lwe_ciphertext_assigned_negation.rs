use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{
    LweCiphertextAssignedNegationEngine, LweCiphertextAssignedNegationError,
};

impl LweCiphertextAssignedNegationEngine<LweCiphertext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     ?;
    /// engine.assigned_neg_lwe_ciphertext(&mut ciphertext)?;
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn assigned_neg_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext32,
    ) -> Result<(), LweCiphertextAssignedNegationError<Self::EngineError>> {
        unsafe { self.assigned_neg_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn assigned_neg_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext32) {
        input.0.update_with_neg();
    }
}

impl LweCiphertextAssignedNegationEngine<LweCiphertext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let plaintext = engine.create_plaintext(&input)?;
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     ?;
    /// engine.assigned_neg_lwe_ciphertext(&mut ciphertext)?;
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn assigned_neg_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext64,
    ) -> Result<(), LweCiphertextAssignedNegationError<Self::EngineError>> {
        unsafe { self.assigned_neg_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn assigned_neg_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext64) {
        input.0.update_with_neg();
    }
}
