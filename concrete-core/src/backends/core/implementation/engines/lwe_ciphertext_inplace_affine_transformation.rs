use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    CleartextVector32, CleartextVector64, LweCiphertext32, LweCiphertext64, LweCiphertextVector32,
    LweCiphertextVector64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextInplaceAffineTransformationEngine, LweCiphertextInplaceAffineTransformationError,
};
use crate::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity,
};

impl
    LweCiphertextInplaceAffineTransformationEngine<
        LweCiphertextVector32,
        CleartextVector32,
        Plaintext32,
        LweCiphertext32,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 15_u32 << 20;
    /// let input_vector = vec![3_u32 << 20; 8];
    /// let weights_input = vec![2_u32; 8];
    /// let bias_input = 8_u32 << 20;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    /// let key: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextVector32 = engine.create_cleartext_vector(&input_vector)?;
    /// let bias: Plaintext32 = engine.create_plaintext(&bias_input)?;
    /// let plaintext_vector: PlaintextVector32 =
    ///     engine.create_plaintext_vector(&input_vector)?;
    /// let plaintext: Plaintext32 = engine.create_plaintext(&input)?;
    /// let ciphertext_vector = engine
    ///     .encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     ?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// engine
    ///     .inplace_affine_transform_lwe_ciphertext(
    ///         &mut output_ciphertext,
    ///         &ciphertext_vector,
    ///         &weights,
    ///         &bias,
    ///     )
    ///     ?;
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(weights)?;
    /// engine.destroy(bias)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(output_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_affine_transform_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) -> Result<(), LweCiphertextInplaceAffineTransformationError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweCiphertextInplaceAffineTransformationError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweCiphertextInplaceAffineTransformationError::CleartextCountMismatch);
        }
        unsafe {
            self.inplace_affine_transform_lwe_ciphertext_unchecked(output, inputs, weights, bias)
        };
        Ok(())
    }

    unsafe fn inplace_affine_transform_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}

impl
    LweCiphertextInplaceAffineTransformationEngine<
        LweCiphertextVector64,
        CleartextVector64,
        Plaintext64,
        LweCiphertext64,
    > for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::LweDimension;
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let lwe_dimension = LweDimension(2);
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 15_u64 << 20;
    /// let input_vector = vec![3_u64 << 50; 8];
    /// let weights_input = vec![2_u64; 8];
    /// let bias_input = 8_u64 << 50;
    /// let noise = Variance::from_variance(2_f64.powf(-25.));
    /// let key: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dimension)?;
    /// let weights: CleartextVector64 = engine.create_cleartext_vector(&input_vector)?;
    /// let bias: Plaintext64 = engine.create_plaintext(&bias_input)?;
    /// let plaintext_vector: PlaintextVector64 =
    ///     engine.create_plaintext_vector(&input_vector)?;
    /// let plaintext: Plaintext64 = engine.create_plaintext(&input)?;
    /// let ciphertext_vector = engine
    ///     .encrypt_lwe_ciphertext_vector(&key, &plaintext_vector, noise)
    ///     ?;
    /// let mut output_ciphertext = engine.zero_encrypt_lwe_ciphertext(&key, noise)?;
    /// engine
    ///     .inplace_affine_transform_lwe_ciphertext(
    ///         &mut output_ciphertext,
    ///         &ciphertext_vector,
    ///         &weights,
    ///         &bias,
    ///     )
    ///     ?;
    /// assert_eq!(output_ciphertext.lwe_dimension(), lwe_dimension);
    /// engine.destroy(key)?;
    /// engine.destroy(weights)?;
    /// engine.destroy(bias)?;
    /// engine.destroy(plaintext_vector)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_vector)?;
    /// engine.destroy(output_ciphertext)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_affine_transform_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) -> Result<(), LweCiphertextInplaceAffineTransformationError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweCiphertextInplaceAffineTransformationError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweCiphertextInplaceAffineTransformationError::CleartextCountMismatch);
        }
        unsafe {
            self.inplace_affine_transform_lwe_ciphertext_unchecked(output, inputs, weights, bias)
        };
        Ok(())
    }

    unsafe fn inplace_affine_transform_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}
