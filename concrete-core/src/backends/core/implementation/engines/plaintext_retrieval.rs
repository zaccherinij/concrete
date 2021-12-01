use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Plaintext32, Plaintext64};
use crate::specification::engines::{PlaintextRetrievalEngine, PlaintextRetrievalError};

impl PlaintextRetrievalEngine<Plaintext32, u32> for CoreEngine {
    fn retrieve_plaintext(
        &mut self,
        plaintext: &Plaintext32,
    ) -> Result<u32, PlaintextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_unchecked(&mut self, plaintext: &Plaintext32) -> u32 {
        plaintext.0 .0
    }
}

impl PlaintextRetrievalEngine<Plaintext64, u64> for CoreEngine {
    fn retrieve_plaintext(
        &mut self,
        plaintext: &Plaintext64,
    ) -> Result<u64, PlaintextRetrievalError<Self::EngineError>> {
        Ok(unsafe { self.retrieve_plaintext_unchecked(plaintext) })
    }

    unsafe fn retrieve_plaintext_unchecked(&mut self, plaintext: &Plaintext64) -> u64 {
        plaintext.0 .0
    }
}
