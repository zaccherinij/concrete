use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Plaintext32, Plaintext64};
use crate::specification::engines::{
    PlaintextInplaceRetrievalEngine, PlaintextInplaceRetrievalError,
};

impl PlaintextInplaceRetrievalEngine<Plaintext32, u32> for CoreEngine {
    fn inplace_retrieve_plaintext(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) -> Result<(), PlaintextInplaceRetrievalError<Self::EngineError>> {
        unsafe { self.inplace_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) {
        *output = input.0 .0;
    }
}

impl PlaintextInplaceRetrievalEngine<Plaintext64, u64> for CoreEngine {
    fn inplace_retrieve_plaintext(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) -> Result<(), PlaintextInplaceRetrievalError<Self::EngineError>> {
        unsafe { self.inplace_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) {
        *output = input.0 .0;
    }
}
