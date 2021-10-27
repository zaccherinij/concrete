use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::backends::core::private::math::tensor::{AsMutTensor, AsRefTensor};
use crate::specification::engines::{
    LweCiphertextInplaceNegationEngine, LweCiphertextInplaceNegationError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextInplaceNegationEngine<LweCiphertext32, LweCiphertext32> for CoreEngine {
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
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// engine
    ///     .inplace_neg_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_neg_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextInplaceNegationError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextInplaceNegationError::LweDimensionMismatch);
        }
        unsafe { self.inplace_neg_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_neg_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}

impl LweCiphertextInplaceNegationEngine<LweCiphertext64, LweCiphertext64> for CoreEngine {
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
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// engine
    ///     .inplace_neg_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_neg_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextInplaceNegationError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextInplaceNegationError::LweDimensionMismatch);
        }
        unsafe { self.inplace_neg_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_neg_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.as_mut_tensor().fill_with_copy(input.0.as_tensor());
        output.0.update_with_neg();
    }
}
