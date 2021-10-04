use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::CiphertextCount;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::backends::core::private::crypto::glwe::GlweList as ImplGlweList;
use crate::specification::engines::{
    GlweCiphertextVectorEncryptionEngine, GlweCiphertextVectorEncryptionError,
};
use crate::specification::entities::{GlweSecretKeyEntity, PlaintextVectorEntity};

impl
    GlweCiphertextVectorEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertextVector32>
    for CoreEngine
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
    /// let key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(
    ///     ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<GlweCiphertextVector32, GlweCiphertextVectorEncryptionError<Self::EngineError>>
    {
        if (input.plaintext_count().0 % key.polynomial_size().0) != 0 {
            return Err(GlweCiphertextVectorEncryptionError::PlaintextCountMismatch);
        }
        Ok(unsafe { self.encrypt_glwe_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> GlweCiphertextVector32 {
        let mut ciphertext_vector = ImplGlweList::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
        );
        key.0.encrypt_glwe_list(
            &mut ciphertext_vector,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertextVector32(ciphertext_vector)
    }
}

impl
    GlweCiphertextVectorEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertextVector64>
    for CoreEngine
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
    /// let key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(
    ///     ciphertext_vector.glwe_ciphertext_count(),
    ///     GlweCiphertextCount(2)
    /// );
    /// assert_eq!(ciphertext_vector.polynomial_size(), polynomial_size);
    /// assert_eq!(ciphertext_vector.glwe_dimension(), glwe_dimension);
    /// engine.destroy(ciphertext_vector).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(key).unwrap();
    /// ```
    fn encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<GlweCiphertextVector64, GlweCiphertextVectorEncryptionError<Self::EngineError>>
    {
        if (input.plaintext_count().0 % key.polynomial_size().0) != 0 {
            return Err(GlweCiphertextVectorEncryptionError::PlaintextCountMismatch);
        }
        Ok(unsafe { self.encrypt_glwe_ciphertext_vector_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> GlweCiphertextVector64 {
        let mut ciphertext_vector = ImplGlweList::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension(),
            CiphertextCount(input.plaintext_count().0 / key.polynomial_size().0),
        );
        key.0.encrypt_glwe_list(
            &mut ciphertext_vector,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertextVector64(ciphertext_vector)
    }
}
