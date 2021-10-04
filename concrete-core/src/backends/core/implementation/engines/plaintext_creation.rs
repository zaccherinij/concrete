use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{Plaintext32, Plaintext64};
use crate::backends::core::private::crypto::encoding::Plaintext as ImplPlaintext;
use crate::specification::engines::{PlaintextCreationEngine, PlaintextCreationError};

impl PlaintextCreationEngine<u32, Plaintext32> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // Here a hard-set encoding is applied (shift by 20 bits)
    /// let input = 3_u32 << 20;
    /// let plaintext: Plaintext32 = engine.create_plaintext(&input).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// ```
    fn create_plaintext(
        &mut self,
        input: &u32,
    ) -> Result<Plaintext32, PlaintextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_plaintext_unchecked(input) })
    }

    unsafe fn create_plaintext_unchecked(&mut self, input: &u32) -> Plaintext32 {
        Plaintext32(ImplPlaintext(*input))
    }
}

impl PlaintextCreationEngine<u64, Plaintext64> for CoreEngine {
    /// # Example:
    /// ```
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // Here a hard-set encoding is applied (shift by 50 bits)
    /// let input = 3_u64 << 50;
    /// let plaintext: Plaintext64 = engine.create_plaintext(&input).unwrap();
    /// engine.destroy(plaintext).unwrap();
    /// ```
    fn create_plaintext(
        &mut self,
        input: &u64,
    ) -> Result<Plaintext64, PlaintextCreationError<Self::EngineError>> {
        Ok(unsafe { self.create_plaintext_unchecked(input) })
    }

    unsafe fn create_plaintext_unchecked(&mut self, input: &u64) -> Plaintext64 {
        Plaintext64(ImplPlaintext(*input))
    }
}
