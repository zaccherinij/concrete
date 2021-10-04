use concrete_commons::dispersion::Variance;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertextVector32, LweCiphertextVector64, LweSecretKey32, LweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    LweCiphertextVectorInplaceEncryptionEngine, LweCiphertextVectorInplaceEncryptionError,
};
use crate::specification::entities::{
    LweCiphertextVectorEntity, LweSecretKeyEntity, PlaintextVectorEntity,
};

impl
    LweCiphertextVectorInplaceEncryptionEngine<
        LweSecretKey32,
        PlaintextVector32,
        LweCiphertextVector32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_vector: PlaintextVector32 = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext_vector: LweCiphertextVector32 = engine
    ///     .encrypt_lwe_ciphertext_vector(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// let key_2: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// engine
    ///     .inplace_encrypt_lwe_ciphertext_vector(
    ///         &key_2,
    ///         &mut ciphertext_vector,
    ///         &plaintext_vector,
    ///         noise,
    ///     )
    ///     .unwrap();
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextVectorInplaceEncryptionError::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(LweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey32,
        output: &mut LweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl
    LweCiphertextVectorInplaceEncryptionEngine<
        LweSecretKey64,
        PlaintextVector64,
        LweCiphertextVector64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{LweCiphertextCount, LweDimension};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(6);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 3];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let plaintext_vector: PlaintextVector64 = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext_vector: LweCiphertextVector64 = engine
    ///     .encrypt_lwe_ciphertext_vector(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// let key_2: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// engine.inplace_encrypt_lwe_ciphertext_vector(
    ///     &key_2,
    ///     &mut ciphertext_vector,
    ///     &plaintext_vector,
    ///     noise,
    /// );
    /// assert_eq!(ciphertext_vector.lwe_dimension(), lwe_dimension);
    /// assert_eq!(
    ///     ciphertext_vector.lwe_ciphertext_count(),
    ///     LweCiphertextCount(3)
    /// );
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_lwe_ciphertext_vector(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), LweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextVectorInplaceEncryptionError::LweDimensionMismatch);
        }
        if input.plaintext_count().0 != output.lwe_ciphertext_count().0 {
            return Err(LweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_lwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_lwe_ciphertext_vector_unchecked(
        &mut self,
        key: &LweSecretKey64,
        output: &mut LweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_lwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
