use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32,
    PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextInplaceDecryptionEngine, GlweCiphertextInplaceDecryptionError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

impl GlweCiphertextInplaceDecryptionEngine<GlweSecretKey32, GlweCiphertext32, PlaintextVector32>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let mut input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let mut plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_glwe_ciphertext(&key, &mut plaintext_vector, &ciphertext)
    ///     .unwrap();
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(4));
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn inplace_decrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertext32,
    ) -> Result<(), GlweCiphertextInplaceDecryptionError<Self::EngineError>> {
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextInplaceDecryptionError::GlweDimensionMismatch);
        }
        if input.polynomial_size().0 != output.plaintext_count().0 {
            return Err(GlweCiphertextInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertext32,
    ) {
        key.0.decrypt_glwe(&mut output.0, &input.0);
    }
}

impl GlweCiphertextInplaceDecryptionEngine<GlweSecretKey64, GlweCiphertext64, PlaintextVector64>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let mut input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let mut plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_decrypt_glwe_ciphertext(&key, &mut plaintext_vector, &ciphertext)
    ///     .unwrap();
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(4));
    /// engine.destroy(ciphertext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn inplace_decrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertext64,
    ) -> Result<(), GlweCiphertextInplaceDecryptionError<Self::EngineError>> {
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextInplaceDecryptionError::GlweDimensionMismatch);
        }
        if input.polynomial_size().0 != output.plaintext_count().0 {
            return Err(GlweCiphertextInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertext64,
    ) {
        key.0.decrypt_glwe(&mut output.0, &input.0);
    }
}
