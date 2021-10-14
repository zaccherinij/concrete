use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextRetrievalError for PlaintextRetrievalEngine @
}

/// A trait for engines retrieving plaintexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a raw value from the `plaintext`
/// plaintext.
///
/// # Formal Definition
pub trait PlaintextRetrievalEngine<Plaintext, Raw>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Retrieves a raw value from a plaintext.
    fn retrieve_plaintext(
        &mut self,
        plaintext: &Plaintext,
    ) -> Result<Raw, PlaintextRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves a raw value from a plaintext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextRetrievalError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn retrieve_plaintext_unchecked(&mut self, plaintext: &Plaintext) -> Raw;
}
