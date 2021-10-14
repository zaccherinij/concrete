use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{LweCiphertext32, LweCiphertext64};
use crate::backends::core::private::math::tensor::AsMutTensor;
use crate::specification::engines::{
    LweCiphertextInplaceAdditionEngine, LweCiphertextInplaceAdditionError,
};
use crate::specification::entities::LweCiphertextEntity;

impl LweCiphertextInplaceAdditionEngine<LweCiphertext32, LweCiphertext32> for CoreEngine {
    fn inplace_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) -> Result<(), LweCiphertextInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(LweCiphertextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input_1: &LweCiphertext32,
        input_2: &LweCiphertext32,
    ) {
        output.0.as_mut_tensor().fill_with_element(0);
        output.0.update_with_add(&input_1.0);
        output.0.update_with_add(&input_2.0);
    }
}

impl LweCiphertextInplaceAdditionEngine<LweCiphertext64, LweCiphertext64> for CoreEngine {
    fn inplace_add_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) -> Result<(), LweCiphertextInplaceAdditionError<Self::EngineError>> {
        if output.lwe_dimension() != input_1.lwe_dimension()
            || output.lwe_dimension() != input_2.lwe_dimension()
        {
            return Err(LweCiphertextInplaceAdditionError::LweDimensionMismatch);
        }
        unsafe { self.inplace_add_lwe_ciphertext_unchecked(output, input_1, input_2) };
        Ok(())
    }

    unsafe fn inplace_add_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input_1: &LweCiphertext64,
        input_2: &LweCiphertext64,
    ) {
        output.0.as_mut_tensor().fill_with_element(0);
        output.0.update_with_add(&input_1.0);
        output.0.update_with_add(&input_2.0);
    }
}
