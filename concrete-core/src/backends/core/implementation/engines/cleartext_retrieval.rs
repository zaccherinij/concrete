use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Cleartext32, Cleartext64};
use crate::specification::engines::{CleartextRetrievalEngine, CleartextRetrievalError};

impl CleartextRetrievalEngine<Cleartext32, u32> for CoreEngine {
    fn retrieve_cleartext(
        &mut self,
        cleartext: &Cleartext32,
    ) -> Result<u32, CleartextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_unchecked(&mut self, cleartext: &Cleartext32) -> u32 {
        cleartext.0 .0
    }
}

impl CleartextRetrievalEngine<Cleartext64, u64> for CoreEngine {
    fn retrieve_cleartext(
        &mut self,
        cleartext: &Cleartext64,
    ) -> Result<u64, CleartextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_cleartext_unchecked(cleartext) })
    }

    unsafe fn retrieve_cleartext_unchecked(&mut self, cleartext: &Cleartext64) -> u64 {
        cleartext.0 .0
    }
}
