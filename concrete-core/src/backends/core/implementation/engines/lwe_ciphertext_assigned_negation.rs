use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{
    LweCiphertextAssignedNegationEngine, LweCiphertextAssignedNegationError,
};

impl LweCiphertextAssignedNegationEngine<LweCiphertext32> for CoreEngine {
    fn assigned_neg_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext32,
    ) -> Result<(), LweCiphertextAssignedNegationError<Self::EngineError>> {
        unsafe { self.assigned_neg_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn assigned_neg_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext32) {
        input.0.update_with_neg();
    }
}

impl LweCiphertextAssignedNegationEngine<LweCiphertext64> for CoreEngine {
    fn assigned_neg_lwe_ciphertext(
        &mut self,
        input: &mut LweCiphertext64,
    ) -> Result<(), LweCiphertextAssignedNegationError<Self::EngineError>> {
        unsafe { self.assigned_neg_lwe_ciphertext_unchecked(input) };
        Ok(())
    }

    unsafe fn assigned_neg_lwe_ciphertext_unchecked(&mut self, input: &mut LweCiphertext64) {
        input.0.update_with_neg();
    }
}
