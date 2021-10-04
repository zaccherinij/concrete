use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextPlaintextAssignedAdditionEngine, LweCiphertextPlaintextAssignedAdditionError,
};

impl LweCiphertextPlaintextAssignedAdditionEngine<LweCiphertext32, Plaintext32> for CoreEngine {
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
    /// let input_2 = 5_u32 << 20;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_1 = engine.create_plaintext(&input_1).unwrap();
    /// let plaintext_2 = engine.create_plaintext(&input_2).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     .unwrap();
    /// engine
    ///     .assigned_add_lwe_ciphertext_plaintext(&mut ciphertext, &plaintext_2)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_1).unwrap();
    /// engine.destroy(plaintext_2).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn assigned_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextAssignedAdditionError<Self::EngineError>> {
        unsafe { self.assigned_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assigned_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) {
        output.0.get_mut_body().0 += input.0 .0;
    }
}

impl LweCiphertextPlaintextAssignedAdditionEngine<LweCiphertext64, Plaintext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 40 bits)
    /// let input_1 = 3_u64 << 40;
    /// let input_2 = 5_u64 << 40;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_1 = engine.create_plaintext(&input_1).unwrap();
    /// let plaintext_2 = engine.create_plaintext(&input_2).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext_1, noise)
    ///     .unwrap();
    /// engine
    ///     .assigned_add_lwe_ciphertext_plaintext(&mut ciphertext, &plaintext_2)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_1).unwrap();
    /// engine.destroy(plaintext_2).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn assigned_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextAssignedAdditionError<Self::EngineError>> {
        unsafe { self.assigned_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assigned_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) {
        output.0.get_mut_body().0 += input.0 .0;
    }
}
