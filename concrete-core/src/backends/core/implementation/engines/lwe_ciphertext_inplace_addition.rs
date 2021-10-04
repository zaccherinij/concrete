use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::backends::core::private::math::tensor::AsMutTensor;
use crate::specification::engines::{
    LweCiphertextInplaceAdditionEngine, LweCiphertextInplaceAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextInplaceAdditionEngine<LweCiphertext32, LweCiphertext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input_1 = 3_u32 << 20;
    /// let input_2 = 7_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_1 = engine.create_plaintext(&input_1).unwrap();
    /// let plaintext_2 = engine.create_plaintext(&input_2).unwrap();
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     .unwrap();
    /// let ciphertext_2 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_2, noise)
    ///     .unwrap();
    /// let mut ciphertext_3 = engine.zero_encrypt_lwe_ciphertext(&key, noise).unwrap();
    /// engine
    ///     .inplace_add_lwe_ciphertext(&mut ciphertext_3, &ciphertext_1, &ciphertext_2)
    ///     .unwrap();
    /// assert_eq!(ciphertext_3.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_1).unwrap();
    /// engine.destroy(plaintext_2).unwrap();
    /// engine.destroy(ciphertext_1).unwrap();
    /// engine.destroy(ciphertext_2).unwrap();
    /// engine.destroy(ciphertext_3).unwrap();
    /// ```
    fn inplace_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) -> Result<(), LweCiphertextInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(LweCiphertextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) {
        output.0.as_mut_tensor().fill_with_element(0);
        output.0.update_with_add(&input_1.0);
        output.0.update_with_add(&input_2.0);
    }
}

impl LweCiphertextInplaceAdditionEngine<LweCiphertext64, LweCiphertext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input_1 = 3_u64 << 50;
    /// let input_2 = 7_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_1 = engine.create_plaintext(&input_1).unwrap();
    /// let plaintext_2 = engine.create_plaintext(&input_2).unwrap();
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     .unwrap();
    /// let ciphertext_2 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_2, noise)
    ///     .unwrap();
    /// let mut ciphertext_3 = engine.zero_encrypt_lwe_ciphertext(&key, noise).unwrap();
    /// engine
    ///     .inplace_add_lwe_ciphertext(&mut ciphertext_3, &ciphertext_1, &ciphertext_2)
    ///     .unwrap();
    /// assert_eq!(ciphertext_3.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_1).unwrap();
    /// engine.destroy(plaintext_2).unwrap();
    /// engine.destroy(ciphertext_1).unwrap();
    /// engine.destroy(ciphertext_2).unwrap();
    /// engine.destroy(ciphertext_3).unwrap();
    /// ```
    fn inplace_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) -> Result<(), LweCiphertextInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(LweCiphertextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) {
        output.0.as_mut_tensor().fill_with_element(0);
        output.0.update_with_add(&input_1.0);
        output.0.update_with_add(&input_2.0);
    }
}
