use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    LweCiphertextVectorInplaceDecryptionEngine, LweCiphertextVectorInplaceDecryptionError,
};
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

impl
    LweCiphertextVectorInplaceDecryptionEngine<
        LweSecretKey32,
        LweCiphertextVector32,
        PlaintextVector32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension, PlaintextCount};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let mut plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext_vector: LweCiphertextVector32 = engine
    ///     .encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_lwe_ciphertext_vector(&key, &mut plaintext_vector, &ciphertext_vector)
    ///     .unwrap();
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(18));
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn inplace_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextVector32,
        input: &LweCiphertextVector32,
    ) -> Result<(), LweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextVectorInplaceDecryptionError::LweDimensionMismatch);
        }
        if input.lwe_ciphertext_count().0 != output.plaintext_count().0 {
            return Err(LweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_lwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut PlaintextVector32,
        input: &LweCiphertextVector32,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}

impl
    LweCiphertextVectorInplaceDecryptionEngine<
        LweSecretKey64,
        LweCiphertextVector64,
        PlaintextVector64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension, PlaintextCount};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 18];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let mut plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext_vector: LweCiphertextVector64 = engine
    ///     .encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_lwe_ciphertext_vector(&key, &mut plaintext_vector, &ciphertext_vector)
    ///     .unwrap();
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(18));
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn inplace_decrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextVector64,
        input: &LweCiphertextVector64,
    ) -> Result<(), LweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextVectorInplaceDecryptionError::LweDimensionMismatch);
        }
        if input.lwe_ciphertext_count().0 != output.plaintext_count().0 {
            return Err(LweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_lwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut PlaintextVector64,
        input: &LweCiphertextVector64,
    ) {
        key.0.decrypt_lwe_list(&mut output.0, &input.0);
    }
}
