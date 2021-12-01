use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Plaintext32, Plaintext64};
use crate::specification::engines::{
    PlaintextDiscardingRetrievalEngine, PlaintextDiscardingRetrievalError,
};

impl PlaintextDiscardingRetrievalEngine<Plaintext32, u32> for CoreEngine {
    fn discarding_retrieve_plaintext(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) -> Result<(), PlaintextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discarding_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Plaintext32,
    ) {
        *output = input.0 .0;
    }
}

impl PlaintextDiscardingRetrievalEngine<Plaintext64, u64> for CoreEngine {
    fn discarding_retrieve_plaintext(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) -> Result<(), PlaintextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discarding_retrieve_plaintext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_plaintext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Plaintext64,
    ) {
        *output = input.0 .0;
    }
}
