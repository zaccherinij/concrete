use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{CleartextVector32, CleartextVector64};
use crate::backends::core::private::math::tensor::AsRefTensor;
use crate::specification::engines::{
    CleartextVectorDiscardingRetrievalEngine, CleartextVectorDiscardingRetrievalError,
};
use crate::specification::entities::CleartextVectorEntity;

impl CleartextVectorDiscardingRetrievalEngine<CleartextVector32, u32> for CoreEngine {
    fn discarding_retrieve_cleartext_vector(
        &mut self,
        output: &mut [u32],
        input: &CleartextVector32,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.cleartext_count().0 {
            return Err(CleartextVectorDiscardingRetrievalError::CleartextCountMismatch);
        }
        unsafe { self.discarding_retrieve_cleartext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [u32],
        input: &CleartextVector32,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}

impl CleartextVectorDiscardingRetrievalEngine<CleartextVector64, u64> for CoreEngine {
    fn discarding_retrieve_cleartext_vector(
        &mut self,
        output: &mut [u64],
        input: &CleartextVector64,
    ) -> Result<(), CleartextVectorDiscardingRetrievalError<Self::EngineError>> {
        if output.len() != input.cleartext_count().0 {
            return Err(CleartextVectorDiscardingRetrievalError::CleartextCountMismatch);
        }
        unsafe { self.discarding_retrieve_cleartext_vector_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_cleartext_vector_unchecked(
        &mut self,
        output: &mut [u64],
        input: &CleartextVector64,
    ) {
        output.copy_from_slice(input.0.as_tensor().as_container().as_slice());
    }
}
