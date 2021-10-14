use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::specification::engines::{
    LweCiphertextAssignedAdditionEngine, LweCiphertextAssignedAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextAssignedAdditionEngine<LweCiphertext32, LweCiphertext32> for CoreEngine {
    fn assign_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) -> Result<(), LweCiphertextAssignedAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextAssignedAdditionError::LweDimensionMismatch);
        }
        unsafe { self.assign_add_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &LweCiphertext32,
    ) {
        output.0.update_with_add(&input.0);
    }
}

impl LweCiphertextAssignedAdditionEngine<LweCiphertext64, LweCiphertext64> for CoreEngine {
    fn assign_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) -> Result<(), LweCiphertextAssignedAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input.lwe_dimension() {
            return Err(LweCiphertextAssignedAdditionError::LweDimensionMismatch);
        }
        unsafe { self.assign_add_lwe_ciphertext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn assign_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &LweCiphertext64,
    ) {
        output.0.update_with_add(&input.0);
    }
}
