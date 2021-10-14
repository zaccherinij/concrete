use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextPlaintextInplaceAdditionEngine, LweCiphertextPlaintextInplaceAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextPlaintextInplaceAdditionEngine<LweCiphertext32, Plaintext32, LweCiphertext32>
    for CoreEngine
{
    fn inplace_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextInplaceAdditionError<Self::EngineError>> {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextPlaintextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Plaintext32,
    ) {
        output.0.get_mut_body().0 = input_1.0.get_body().0 + input_2.0 .0;
    }
}

impl LweCiphertextPlaintextInplaceAdditionEngine<LweCiphertext64, Plaintext64, LweCiphertext64>
    for CoreEngine
{
    fn inplace_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextInplaceAdditionError<Self::EngineError>> {
        if input_1.lwe_dimension() != output.lwe_dimension() {
            return Err(LweCiphertextPlaintextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_plaintext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Plaintext64,
    ) {
        output.0.get_mut_body().0 = input_1.0.get_body().0 + input_2.0 .0;
    }
}
