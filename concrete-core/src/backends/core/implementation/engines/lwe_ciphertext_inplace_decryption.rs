use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweSecretKey32, LweSecretKey64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextInplaceDecryptionEngine, LweCiphertextInplaceDecryptionError,
};
use crate::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity};

impl LweCiphertextInplaceDecryptionEngine<LweSecretKey32, LweCiphertext32, Plaintext32>
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
    /// let mut plaintext = engine.create_plaintext(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_lwe_ciphertext(&key, &mut plaintext, &ciphertext)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn inplace_decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey32,
        output: &mut Plaintext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextInplaceDecryptionError<Self::EngineError>> {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextInplaceDecryptionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_decrypt_lwe_ciphertext_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut Plaintext32,
        input: &LweCiphertext32,
    ) {
        key.0.decrypt_lwe(&mut output.0, &input.0);
    }
}

impl LweCiphertextInplaceDecryptionEngine<LweSecretKey64, LweCiphertext64, Plaintext64>
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
    /// let mut plaintext = engine.create_plaintext(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_lwe_ciphertext(&key, &plaintext, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_lwe_ciphertext(&key, &mut plaintext, &ciphertext)
    ///     .unwrap();
    /// assert_eq!(ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn inplace_decrypt_lwe_ciphertext(
        &mut self,
        key: &LweSecretKey64,
        output: &mut Plaintext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextInplaceDecryptionError<Self::EngineError>> {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextInplaceDecryptionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_decrypt_lwe_ciphertext_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut Plaintext64,
        input: &LweCiphertext64,
    ) {
        key.0.decrypt_lwe(&mut output.0, &input.0);
    }
}
