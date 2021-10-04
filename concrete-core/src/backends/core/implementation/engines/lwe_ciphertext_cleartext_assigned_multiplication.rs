use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextCleartextAssignedMultiplicationEngine,
    LweCiphertextCleartextAssignedMultiplicationError,
};

impl LweCiphertextCleartextAssignedMultiplicationEngine<LweCiphertext32, Cleartext32>
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
    /// let cleartext_input = 12_u32;
    /// let cleartext: Cleartext32 = engine.create_cleartext(&cleartext_input).unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// engine
    ///     .assign_mul_lwe_ciphertext_cleartext(&mut ciphertext, &cleartext)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(cleartext).unwrap();
    /// ```
    fn assign_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextAssignedMultiplicationError<Self::EngineError>> {
        unsafe { self.assign_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}

impl LweCiphertextCleartextAssignedMultiplicationEngine<LweCiphertext64, Cleartext64>
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
    /// let cleartext_input = 12_u64;
    /// let cleartext: Cleartext64 = engine.create_cleartext(&cleartext_input).unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// engine
    ///     .assign_mul_lwe_ciphertext_cleartext(&mut ciphertext, &cleartext)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(cleartext).unwrap();
    /// ```
    fn assign_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextAssignedMultiplicationError<Self::EngineError>> {
        unsafe { self.assign_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}
