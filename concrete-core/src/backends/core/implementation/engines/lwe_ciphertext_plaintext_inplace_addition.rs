use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextPlaintextInplaceAdditionEngine, LweCiphertextPlaintextInplaceAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextPlaintextInplaceAdditionEngine<LweCiphertext32, Plaintext32, LweCiphertext32>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise).unwrap();
    /// engine
    ///     .inplace_add_lwe_ciphertext_plaintext(&mut ciphertext_2, &ciphertext_1, &plaintext)
    ///     .unwrap();
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext_1).unwrap();
    /// engine.destroy(ciphertext_2).unwrap();
    /// ```
    fn inplace_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextInplaceAdditionError<Self::EngineError>> {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextPlaintextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) {
        output.0.get_mut_body().0 = input_1.0.get_body().0 + input_2.0 .0;
    }
}

impl LweCiphertextPlaintextInplaceAdditionEngine<LweCiphertext64, Plaintext64, LweCiphertext64>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// let mut ciphertext_2 = engine.zero_encrypt_lwe_ciphertext(&key, noise).unwrap();
    /// engine
    ///     .inplace_add_lwe_ciphertext_plaintext(&mut ciphertext_2, &ciphertext_1, &plaintext)
    ///     .unwrap();
    /// assert_eq!(ciphertext_2.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext_1).unwrap();
    /// engine.destroy(ciphertext_2).unwrap();
    /// ```
    fn inplace_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextInplaceAdditionError<Self::EngineError>> {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextPlaintextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) {
        output.0.get_mut_body().0 = input_1.0.get_body().0 + input_2.0 .0;
    }
}
