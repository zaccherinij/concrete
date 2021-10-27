use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextVectorInplaceDecryptionEngine, GlweCiphertextVectorInplaceDecryptionError,
};
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

impl
    GlweCiphertextVectorInplaceDecryptionEngine<
        GlweSecretKey32,
        GlweCiphertextVector32,
        PlaintextVector32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     ?;
    /// let mut plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     ?;
    /// engine
    ///     .inplace_decrypt_glwe_ciphertext_vector(&key, &mut plaintext_vector, &ciphertext_vector)
    ///     ?;
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(8));
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) -> Result<(), GlweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0 != (key.polynomial_size().0 * key.glwe_dimension().0) {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}

impl
    GlweCiphertextVectorInplaceDecryptionEngine<
        GlweSecretKey64,
        GlweCiphertextVector64,
        PlaintextVector64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{GlweDimension, PlaintextCount, PolynomialSize};
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; 8];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     ?;
    /// let mut plaintext_vector = engine.create_plaintext_vector(&input)?;
    /// let ciphertext_vector = engine
    ///     .encrypt_glwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     ?;
    /// engine
    ///     .inplace_decrypt_glwe_ciphertext_vector(&key, &mut plaintext_vector, &ciphertext_vector)
    ///     ?;
    /// assert_eq!(plaintext_vector.plaintext_count(), PlaintextCount(8));
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(key)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) -> Result<(), GlweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0 != (key.polynomial_size().0 * key.glwe_dimension().0) {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}
