use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    LweCiphertext32, LweCiphertext64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextPlaintextAssignedAdditionEngine, LweCiphertextPlaintextAssignedAdditionError,
};

impl LweCiphertextPlaintextAssignedAdditionEngine<LweCiphertext32, Plaintext32> for CoreEngine {
    fn assigned_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) -> Result<(), LweCiphertextPlaintextAssignedAdditionError<Self::EngineError>> {
        unsafe { self.assigned_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assigned_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &Plaintext32,
    ) {
        output.0.get_mut_body().0 += input.0 .0;
    }
}

impl LweCiphertextPlaintextAssignedAdditionEngine<LweCiphertext64, Plaintext64> for CoreEngine {
    fn assigned_add_lwe_ciphertext_plaintext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) -> Result<(), LweCiphertextPlaintextAssignedAdditionError<Self::EngineError>> {
        unsafe { self.assigned_add_lwe_ciphertext_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assigned_add_lwe_ciphertext_plaintext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &Plaintext64,
    ) {
        output.0.get_mut_body().0 += input.0 .0;
    }
}
