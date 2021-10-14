use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextCleartextInplaceMultiplicationEngine,
    LweCiphertextCleartextInplaceMultiplicationError,
};
use crate::specification::entities::LweCiphertextEntity;

impl
    LweCiphertextCleartextInplaceMultiplicationEngine<LweCiphertext32, Cleartext32, LweCiphertext32>
    for CoreEngine
{
    fn inplace_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextInplaceMultiplicationError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension() {
            return Err(LweCiphertextCleartextInplaceMultiplicationError::LweDimensionMismatch);
        }
        unsafe { self.inplace_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &Cleartext32,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}

impl
    LweCiphertextCleartextInplaceMultiplicationEngine<LweCiphertext64, Cleartext64, LweCiphertext64>
    for CoreEngine
{
    fn inplace_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextInplaceMultiplicationError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension() {
            return Err(LweCiphertextCleartextInplaceMultiplicationError::LweDimensionMismatch);
        }
        unsafe { self.inplace_mul_lwe_ciphertext_cleartext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &Cleartext64,
    ) {
        output.0.fill_with_scalar_mul(&input_1.0, &input_2.0);
    }
}
