use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextCreationError for PlaintextCreationEngine @
}

/// A trait for engines creating plaintexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a plaintext from the `raw` value.
///
/// # Formal Definition
pub trait PlaintextCreationEngine<Raw, Plaintext>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Creates a plaintext from a raw value.
    fn create_plaintext(
        &mut self,
        input: &Raw,
    ) -> Result<Plaintext, PlaintextCreationError<Self::EngineError>>;

    /// Unsafely creates a plaintext from a raw value.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextCreationError`]. For safety concerns _specific_ to an engine, refer to the
    /// implementer safety section.
    unsafe fn create_plaintext_unchecked(&mut self, input: &Raw) -> Plaintext;
}
