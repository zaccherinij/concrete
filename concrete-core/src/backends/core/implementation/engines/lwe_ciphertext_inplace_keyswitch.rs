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
