use concrete_commons::dispersion::Variance;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32,
    PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextInplaceEncryptionEngine, GlweCiphertextInplaceEncryptionError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

impl GlweCiphertextInplaceEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertext32>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 4];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// engine
    ///     .inplace_encrypt_glwe_ciphertext(&key_2, &mut ciphertext, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), GlweCiphertextInplaceEncryptionError<Self::EngineError>> {
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size().0 != input.plaintext_count().0 {
            return Err(GlweCiphertextInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertext32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_glwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl GlweCiphertextInplaceEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertext64>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 4];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key_1: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let mut ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key_1, &plaintext_vector, noise)
    ///     .unwrap();
    /// // We're going to re-encrypt the input with another secret key
    /// // For this, it is required that the second secret key uses the same GLWE dimension
    /// // and polynomial size as the first one.
    /// let key_2: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// engine
    ///     .inplace_encrypt_glwe_ciphertext(&key_2, &mut ciphertext, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key_1).unwrap();
    /// engine.destroy(key_2).unwrap();
    /// ```
    fn inplace_encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), GlweCiphertextInplaceEncryptionError<Self::EngineError>> {
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size().0 != input.plaintext_count().0 {
            return Err(GlweCiphertextInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertext64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_glwe(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
