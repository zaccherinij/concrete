use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Cleartext32, Cleartext64};
use crate::specification::engines::{
    CleartextInplaceRetrievalEngine, CleartextInplaceRetrievalError,
};

impl CleartextInplaceRetrievalEngine<Cleartext32, u32> for CoreEngine {
    fn inplace_retrieve_cleartext(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) -> Result<(), CleartextInplaceRetrievalError<Self::EngineError>> {
        unsafe { self.inplace_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u32,
        input: &Cleartext32,
    ) {
        *output = input.0 .0;
    }
}

impl CleartextInplaceRetrievalEngine<Cleartext64, u64> for CoreEngine {
    fn inplace_retrieve_cleartext(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) -> Result<(), CleartextInplaceRetrievalError<Self::EngineError>> {
        unsafe { self.inplace_retrieve_cleartext_unchecked(output, input) };
        Ok(())
    }

    unsafe fn inplace_retrieve_cleartext_unchecked(
        &mut self,
        output: &mut u64,
        input: &Cleartext64,
    ) {
        *output = input.0 .0;
    }
}
