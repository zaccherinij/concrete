use concrete_commons::parameters::MonomialDegree;

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextInplaceExtractionEngine, LweCiphertextInplaceExtractionError,
};
use crate::specification::entities::GlweCiphertextEntity;

impl LweCiphertextInplaceExtractionEngine<GlweCiphertext32, LweCiphertext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     GlweDimension, LweDimension, MonomialDegree, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = vec![3_u32 << 20; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let glwe_key: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let glwe_ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)
    ///     .unwrap();
    /// // We first create an LWE ciphertext encrypting zeros
    /// let lwe_key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let mut lwe_ciphertext = engine.zero_encrypt_lwe_ciphertext(&lwe_key, noise).unwrap();
    /// // Then we extract the first sample from the GLWE ciphertext to store it into the LWE
    /// let lwe_key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// engine
    ///     .inplace_extract_lwe_ciphertext(&mut lwe_ciphertext, &glwe_ciphertext, MonomialDegree(0))
    ///     .unwrap();
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(glwe_key).unwrap();
    /// engine.destroy(lwe_key).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(glwe_ciphertext).unwrap();
    /// engine.destroy(lwe_ciphertext).unwrap();
    /// ```
    fn inplace_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialDegree,
    ) -> Result<(), LweCiphertextInplaceExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(LweCiphertextInplaceExtractionError::SizeMismatch);
        }
        if nth.0 > input.glwe_dimension().0 - 1 {
            return Err(LweCiphertextInplaceExtractionError::MonomialDegreeTooLarge);
        }
        unsafe { self.inplace_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn inplace_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}

impl LweCiphertextInplaceExtractionEngine<GlweCiphertext64, LweCiphertext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     GlweDimension, LweDimension, MonomialDegree, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// // The target LWE dimension should be equal to the polynomial size + 1
    /// // since we're going to extract one sample from the GLWE ciphertext
    /// let lwe_dimension = LweDimension(8);
    /// let glwe_dimension = GlweDimension(2);
    /// let polynomial_size = PolynomialSize(4);
    /// // There are always polynomial_size messages encrypted in the GLWE ciphertext
    /// // We're going to extract the first one
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = vec![3_u64 << 50; polynomial_size.0];
    /// let noise = Variance(2_f64.powf(-25.));
    /// let glwe_key: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dimension, polynomial_size)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&input).unwrap();
    /// let glwe_ciphertext = engine
    ///     .encrypt_glwe_ciphertext(&glwe_key, &plaintext_vector, noise)
    ///     .unwrap();
    /// // We first create an LWE ciphertext encrypting zeros
    /// let lwe_key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// let mut lwe_ciphertext = engine.zero_encrypt_lwe_ciphertext(&lwe_key, noise).unwrap();
    /// // Then we extract the first sample from the GLWE ciphertext to store it into the LWE
    /// let lwe_key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension).unwrap();
    /// engine
    ///     .inplace_extract_lwe_ciphertext(&mut lwe_ciphertext, &glwe_ciphertext, MonomialDegree(0))
    ///     .unwrap();
    /// assert_eq!(lwe_ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(glwe_key).unwrap();
    /// engine.destroy(lwe_key).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(glwe_ciphertext).unwrap();
    /// engine.destroy(lwe_ciphertext).unwrap();
    /// ```
    fn inplace_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialDegree,
    ) -> Result<(), LweCiphertextInplaceExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(LweCiphertextInplaceExtractionError::SizeMismatch);
        }
        if nth.0 > input.glwe_dimension().0 - 1 {
            return Err(LweCiphertextInplaceExtractionError::MonomialDegreeTooLarge);
        }
        unsafe { self.inplace_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn inplace_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}
