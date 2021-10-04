use concrete_commons::dispersion::Variance;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextVectorInplaceEncryptionEngine, GlweCiphertextVectorInplaceEncryptionError,
};
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

impl
    GlweCiphertextVectorInplaceEncryptionEngine<
        GlweSecretKey32,
        PlaintextVector32,
        GlweCiphertextVector32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let key_2: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_encrypt_glwe_ciphertext_vector(
    ///         &key_2,
    ///         &mut ciphertext_vector,
    ///         &plaintext_vector,
    ///         noise,
    ///     )
    ///     .unwrap();
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(
    ///     ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl
    GlweCiphertextVectorInplaceEncryptionEngine<
        GlweSecretKey64,
        PlaintextVector64,
        GlweCiphertextVector64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let key_2: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_encrypt_glwe_ciphertext_vector(
    ///         &key_2,
    ///         &mut ciphertext_vector,
    ///         &plaintext_vector,
    ///         noise,
    ///     )
    ///     .unwrap();
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(
    ///     ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
