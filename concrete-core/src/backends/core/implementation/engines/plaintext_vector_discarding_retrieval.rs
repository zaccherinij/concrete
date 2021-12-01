use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{PlaintextVector32, PlaintextVector64};
use crate::backends::core::private::math::tensor::AsRefTensor;
use crate::specification::engines::{
    PlaintextVectorDiscardingRetrievalEngine, PlaintextVectorDiscardingRetrievalError,
};
use crate::specification::entities::PlaintextVectorEntity;

impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector32, u32> for CoreEngine {
    fn discarding_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.plaintext_count().0 {
            return Err(PlaintextVectorDiscardingRetrievalError::PlaintextCountMismatch);
        }
        unsafe { self.discarding_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u32],
        input: &PlaintextVector32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

impl PlaintextVectorDiscardingRetrievalEngine<PlaintextVector64, u64> for CoreEngine {
    fn discarding_retrieve_plaintext_vector(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) -> Result<(), PlaintextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.plaintext_count().0 {
            return Err(PlaintextVectorDiscardingRetrievalError::PlaintextCountMismatch);
        }
        unsafe { self.discarding_retrieve_plaintext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_plaintext_vector_unchecked(
        &mut self,
        output: &mut [u64],
        input: &PlaintextVector64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
