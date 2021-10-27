use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, LweKeyswitchKey32, LweKeyswitchKey64,
};
use crate::specification::engines::{
    LweCiphertextInplaceKeyswitchEngine, LweCiphertextInplaceKeyswitchError,
};
use crate::specification::entities::{LweCiphertextEntity, LweKeyswitchKeyEntity};

impl LweCiphertextInplaceKeyswitchEngine<LweKeyswitchKey32, LweCiphertext32, LweCiphertext32>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    /// let input_key: LweSecretKey32 = engine.generate_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey32 = engine
    ///     .generate_lwe_secret_key(output_lwe_dimension)
    ///     ?;
    /// let keyswitch_key = engine
    ///     .generate_lwe_keyswitch_key(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_level_count,
    ///         decomposition_base_log,
    ///         noise,
    ///     )
    ///     ?;
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let plaintext = engine.create_plaintext(&input)?;
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&input_key, &plaintext, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine
    ///     .zero_encrypt_lwe_ciphertext(&output_key, noise)
    ///     ?;
    /// engine
    ///     .inplace_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(keyswitch_key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        ksk: &LweKeyswitchKey32,
    ) -> Result<(), LweCiphertextInplaceKeyswitchError<Self::EngineError>> {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(LweCiphertextInplaceKeyswitchError::InputLweDimensionMismatch);
        }
        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(LweCiphertextInplaceKeyswitchError::OutputLweDimensionMismatch);
        }
        unsafe { self.inplace_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn inplace_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
        ksk: &LweKeyswitchKey32,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}

impl LweCiphertextInplaceKeyswitchEngine<LweKeyswitchKey64, LweCiphertext64, LweCiphertext64>
    for CoreEngine
{
    /// # Example:
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, LweDimension,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let input_lwe_dimension = LweDimension(6);
    /// let output_lwe_dimension = LweDimension(3);
    /// let decomposition_level_count = DecompositionLevelCount(2);
    /// let decomposition_base_log = DecompositionBaseLog(8);
    /// let noise = Variance(2_f64.powf(-25.));
    /// let input_key: LweSecretKey64 = engine.generate_lwe_secret_key(input_lwe_dimension)?;
    /// let output_key: LweSecretKey64 = engine
    ///     .generate_lwe_secret_key(output_lwe_dimension)
    ///     ?;
    /// let keyswitch_key = engine
    ///     .generate_lwe_keyswitch_key(
    ///         &input_key,
    ///         &output_key,
    ///         decomposition_level_count,
    ///         decomposition_base_log,
    ///         noise,
    ///     )
    ///     ?;
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let plaintext = engine.create_plaintext(&input)?;
    /// let ciphertext_1 = engine
    ///     .encrypt_lwe_ciphertext(&input_key, &plaintext, noise)
    ///     ?;
    /// let mut ciphertext_2 = engine
    ///     .zero_encrypt_lwe_ciphertext(&output_key, noise)
    ///     ?;
    /// engine
    ///     .inplace_keyswitch_lwe_ciphertext(&mut ciphertext_2, &ciphertext_1, &keyswitch_key)
    ///     ?;
    /// assert_eq!(ciphertext_2.lwe_dimension(), output_lwe_dimension);
    /// engine.destroy(input_key)?;
    /// engine.destroy(output_key)?;
    /// engine.destroy(keyswitch_key)?;
    /// engine.destroy(plaintext)?;
    /// engine.destroy(ciphertext_1)?;
    /// engine.destroy(ciphertext_2)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn inplace_keyswitch_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        ksk: &LweKeyswitchKey64,
    ) -> Result<(), LweCiphertextInplaceKeyswitchError<Self::EngineError>> {
        if input.lwe_dimension() != ksk.input_lwe_dimension() {
            return Err(LweCiphertextInplaceKeyswitchError::InputLweDimensionMismatch);
        }
        if output.lwe_dimension() != ksk.output_lwe_dimension() {
            return Err(LweCiphertextInplaceKeyswitchError::OutputLweDimensionMismatch);
        }
        unsafe { self.inplace_keyswitch_lwe_ciphertext_unchecked(output, input, ksk) };
        Ok(())
    }

    unsafe fn inplace_keyswitch_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
        ksk: &LweKeyswitchKey64,
    ) {
        ksk.0.keyswitch_ciphertext(&mut output.0, &input.0);
    }
}
