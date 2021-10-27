use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{
    LweCiphertextAssignedAdditionEngine, LweCiphertextAssignedAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextAssignedAdditionEngine<LweCiphertext32, LweCiphertext32> for CoreEngine {
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
    /// let input_1 = 3_u32 << 20;
    /// let input_2 = 5_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext(&input_2)?;
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_2, noise)
    ///     ?;
    /// engine
    ///     .assign_add_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_1)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(plaintext_2)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn assign_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextAssignedAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextAssignedAdditionError::LweDimensionMismatch);
        }
        unsafe { self.assign_add_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.update_with_add(&input.0);
    }
}

impl LweCiphertextAssignedAdditionEngine<LweCiphertext64, LweCiphertext64> for CoreEngine {
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
    /// let input_1 = 3_u64 << 50;
    /// let input_2 = 5_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let plaintext_1 = engine.create_plaintext(&input_1)?;
    /// let plaintext_2 = engine.create_plaintext(&input_2)?;
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_2, noise)
    ///     ?;
    /// engine
    ///     .assign_add_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext_1)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(plaintext_2)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn assign_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextAssignedAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextAssignedAdditionError::LweDimensionMismatch);
        }
        unsafe { self.assign_add_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.update_with_add(&input.0);
    }
}
