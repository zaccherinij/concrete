use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64,
    LweCiphertext32, LweCiphertext64,
};
use crate::backends::core::private::crypto::bootstrap::Bootstrap;
use crate::specification::engines::{
    LweCiphertextInplaceBootstrapEngine, LweCiphertextInplaceBootstrapError,
};
use crate::specification::entities::{
    GlweCiphertextEntity, LweBootstrapKeyEntity, LweCiphertextEntity,
};

impl
    LweCiphertextInplaceBootstrapEngine<
        FourierLweBootstrapKey32,
        GlweCiphertext32,
        LweCiphertext32,
        LweCiphertext32,
    > for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u32 << 20; poly_size.0];
    /// let lwe_sk: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: FourierLweBootstrapKey32 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let input = engine
    ///     .encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)
    ///     .unwrap();
    /// let lwe_sk_output: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dim_output).unwrap();
    /// let mut output = engine
    ///     .zero_encrypt_lwe_ciphertext(&lwe_sk_output, noise)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&lut).unwrap();
    /// let acc = engine
    ///     .encrypt_glwe_ciphertext(&glwe_sk, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)
    ///     .unwrap();
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    /// engine.destroy(lwe_sk).unwrap();
    /// engine.destroy(lwe_sk_output).unwrap();
    /// engine.destroy(glwe_sk).unwrap();
    /// engine.destroy(bsk).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(input).unwrap();
    /// engine.destroy(output).unwrap();
    /// engine.destroy(acc).unwrap();
    /// ```
    fn inplace_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FourierLweBootstrapKey32,
    ) -> Result<(), LweCiphertextInplaceBootstrapError<Self::EngineError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextInplaceBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::OutputLweDimensionMismatch);
        }
        unsafe { self.inplace_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn inplace_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        acc: &GlweCiphertext32,
        bsk: &FourierLweBootstrapKey32,
    ) {
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0);
    }
}

impl
    LweCiphertextInplaceBootstrapEngine<
        FourierLweBootstrapKey64,
        GlweCiphertext64,
        LweCiphertext64,
        LweCiphertext64,
    > for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, lwe_dim_output, glwe_dim, poly_size) = (
    ///     LweDimension(4),
    ///     LweDimension(1024),
    ///     GlweDimension(1),
    ///     PolynomialSize(1024),
    /// );
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// // A constant function is applied during the bootstrap
    /// let lut = vec![8_u64 << 50; poly_size.0];
    /// let lwe_sk: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: FourierLweBootstrapKey64 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// let plaintext = engine.create_plaintext(&input).unwrap();
    /// let input = engine
    ///     .encrypt_lwe_ciphertext(&lwe_sk, &plaintext, noise)
    ///     .unwrap();
    /// let lwe_sk_output: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim_output).unwrap();
    /// let mut output = engine
    ///     .encrypt_lwe_ciphertext(&lwe_sk_output, &plaintext, noise)
    ///     .unwrap();
    /// let plaintext_vector = engine.create_plaintext_vector(&lut).unwrap();
    /// let acc = engine
    ///     .encrypt_glwe_ciphertext(&glwe_sk, &plaintext_vector, noise)
    ///     .unwrap();
    /// engine
    ///     .inplace_bootstrap_lwe_ciphertext(&mut output, &input, &acc, &bsk)
    ///     .unwrap();
    /// assert_eq!(output.lwe_dimension(), lwe_dim_output);
    /// engine.destroy(lwe_sk).unwrap();
    /// engine.destroy(lwe_sk_output).unwrap();
    /// engine.destroy(glwe_sk).unwrap();
    /// engine.destroy(bsk).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// engine.destroy(plaintext_vector).unwrap();
    /// engine.destroy(input).unwrap();
    /// engine.destroy(output).unwrap();
    /// engine.destroy(acc).unwrap();
    /// ```
    fn inplace_bootstrap_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FourierLweBootstrapKey64,
    ) -> Result<(), LweCiphertextInplaceBootstrapError<Self::EngineError>> {
        if input.lwe_dimension() != bsk.input_lwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::InputLweDimensionMismatch);
        }
        if acc.polynomial_size() != bsk.polynomial_size() {
            return Err(LweCiphertextInplaceBootstrapError::AccumulatorPolynomialSizeMismatch);
        }
        if acc.glwe_dimension() != bsk.glwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::AccumulatorGlweDimensionMismatch);
        }
        if output.lwe_dimension() != bsk.output_lwe_dimension() {
            return Err(LweCiphertextInplaceBootstrapError::OutputLweDimensionMismatch);
        }
        unsafe { self.inplace_bootstrap_lwe_ciphertext_unchecked(output, input, acc, bsk) };
        Ok(())
    }

    unsafe fn inplace_bootstrap_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        acc: &GlweCiphertext64,
        bsk: &FourierLweBootstrapKey64,
    ) {
        bsk.0.bootstrap(&mut output.0, &input.0, &acc.0);
    }
}
