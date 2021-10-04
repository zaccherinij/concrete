use concrete_commons::dispersion::Variance;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32,
    PlaintextVector64,
};
use crate::backends::core::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::specification::engines::{
    GlweCiphertextEncryptionEngine, GlweCiphertextEncryptionError,
};
use crate::specification::entities::GlweSecretKeyEntity;

impl GlweCiphertextEncryptionEngine<GlweSecretKey32, PlaintextVector32, GlweCiphertext32>
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
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<GlweCiphertext32, GlweCiphertextEncryptionError<Self::EngineError>> {
        if key.0.polynomial_size().0 != input.0.count().0 {
            return Err(GlweCiphertextEncryptionError::PlaintextCountMismatch);
        }
        Ok(unsafe { self.encrypt_glwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> GlweCiphertext32 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u32,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0.encrypt_glwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertext32(ciphertext)
    }
}

impl GlweCiphertextEncryptionEngine<GlweSecretKey64, PlaintextVector64, GlweCiphertext64>
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
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&key, &plaintext_vector, noise)
    ///     .unwrap();
    /// assert_eq!(ciphertext.glwe_dimension(), glwe_dimension);
    /// assert_eq!(ciphertext.polynomial_size(), polynomial_size);
    /// engine.destroy(key).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(ciphertext).unwrap();
    /// ```
    fn encrypt_glwe_ciphertext(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<GlweCiphertext64, GlweCiphertextEncryptionError<Self::EngineError>> {
        if key.0.polynomial_size().0 != input.0.count().0 {
            return Err(GlweCiphertextEncryptionError::PlaintextCountMismatch);
        }
        Ok(unsafe { self.encrypt_glwe_ciphertext_unchecked(key, input, noise) })
    }

    unsafe fn encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> GlweCiphertext64 {
        let mut ciphertext = ImplGlweCiphertext::allocate(
            0u64,
            key.polynomial_size(),
            key.glwe_dimension().to_glwe_size(),
        );
        key.0.encrypt_glwe(
            &mut ciphertext,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
        GlweCiphertext64(ciphertext)
    }
}
