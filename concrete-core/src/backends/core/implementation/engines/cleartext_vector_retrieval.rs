use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{CleartextVector32, CleartextVector64};
use crate::backends::core::private::math::tensor::AsRefTensor;
use crate::specification::engines::{
    CleartextVectorRetrievalEngine, CleartextVectorRetrievalError,
};

impl CleartextVectorRetrievalEngine<CleartextVector32, u32> for CoreEngine {
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector32,
    ) -> Result<Vec<u32>, CleartextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_vector_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector32,
    ) -> Vec<u32> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}

impl CleartextVectorRetrievalEngine<CleartextVector64, u64> for CoreEngine {
    fn retrieve_cleartext_vector(
        &mut self,
        cleartext: &CleartextVector64,
    ) -> Result<Vec<u64>, CleartextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_vector_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_vector_unchecked(
        &mut self,
        cleartext: &CleartextVector64,
    ) -> Vec<u64> {
        cleartext.0.as_tensor().as_container().to_vec()
    }
}
