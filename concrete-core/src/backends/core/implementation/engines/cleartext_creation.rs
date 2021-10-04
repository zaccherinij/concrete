use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Cleartext32, Cleartext64};
use crate::backends::core::private::crypto::encoding::Cleartext as ImplCleartext;
use crate::specification::engines::{CleartextCreationEngine, CleartextCreationError};

impl CleartextCreationEngine<u32, Cleartext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// let input: u32 = 3;
    /// let cleartext: Cleartext32 = engine.create_cleartext(&input).unwrap();
    /// engine.destroy(cleartext).unwrap();
    /// ```
    fn create_cleartext(
        &mut self,
        input: &u32,
    ) -> Result<Cleartext32, CleartextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_cleartext_unchecked(input) })
    }

    unsafe fn create_cleartext_unchecked(&mut self, input: &u32) -> Cleartext32 {
        Cleartext32(ImplCleartext(*input))
    }
}

impl CleartextCreationEngine<u64, Cleartext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// let input: u64 = 3;
    /// let cleartext: Cleartext64 = engine.create_cleartext(&input).unwrap();
    /// engine.destroy(cleartext).unwrap();
    /// ```
    fn create_cleartext(
        &mut self,
        input: &u64,
    ) -> Result<Cleartext64, CleartextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_cleartext_unchecked(input) })
    }

    unsafe fn create_cleartext_unchecked(&mut self, input: &u64) -> Cleartext64 {
        Cleartext64(ImplCleartext(*input))
    }
}
