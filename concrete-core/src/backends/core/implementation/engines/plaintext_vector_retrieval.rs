use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{PlaintextVector32, PlaintextVector64};
use crate::backends::core::private::math::tensor::AsRefTensor;
use crate::specification::engines::{
    PlaintextVectorRetrievalEngine, PlaintextVectorRetrievalError,
};

impl PlaintextVectorRetrievalEngine<PlaintextVector32, u32> for CoreEngine {
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector32,
    ) -> Result<Vec<u32>, PlaintextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_vector_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector32,
    ) -> Vec<u32> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}

impl PlaintextVectorRetrievalEngine<PlaintextVector64, u64> for CoreEngine {
    fn retrieve_plaintext_vector(
        &mut self,
        plaintext: &PlaintextVector64,
    ) -> Result<Vec<u64>, PlaintextVectorRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_vector_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_vector_unchecked(
        &mut self,
        plaintext: &PlaintextVector64,
    ) -> Vec<u64> {
        plaintext.0.as_tensor().as_container().to_vec()
    }
}
