use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Cleartext32, Cleartext64};
use crate::specification::engines::{
    CleartextDiscardingRetrievalEngine, CleartextDiscardingRetrievalError,
};

impl CleartextDiscardingRetrievalEngine<Cleartext32, u32> for CoreEngine {
    fn discarding_retrieve_cleartext(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discarding_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) {
        *output = input.0 .0;
    }
}

impl CleartextDiscardingRetrievalEngine<Cleartext64, u64> for CoreEngine {
    fn discarding_retrieve_cleartext(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>> {
        unsafe { self.discarding_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn discarding_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) {
        *output = input.0 .0;
    }
}
