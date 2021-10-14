use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextCleartextAssignedMultiplicationEngine,
    LweCiphertextCleartextAssignedMultiplicationError,
};

impl LweCiphertextCleartextAssignedMultiplicationEngine<LweCiphertext32, Cleartext32>
    for CoreEngine
{
    fn assign_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) -> Result<(), LweCiphertextCleartextAssignedMultiplicationError<Self::EngineError>> {
        unsafe { self.assign_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Cleartext32,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}

impl LweCiphertextCleartextAssignedMultiplicationEngine<LweCiphertext64, Cleartext64>
    for CoreEngine
{
    fn assign_mul_lwe_ciphertext_cleartext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) -> Result<(), LweCiphertextCleartextAssignedMultiplicationError<Self::EngineError>> {
        unsafe { self.assign_mul_lwe_ciphertext_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_mul_lwe_ciphertext_cleartext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Cleartext64,
    ) {
        output.0.update_with_scalar_mul(input.0);
    }
}
