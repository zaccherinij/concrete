use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextEntity;

engine_error! {
    CleartextCreationError for CleartextCreationEngine @
}

/// A trait for engines creating cleartexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates a cleartext from the `raw` value.
///
/// # Formal Definition
pub trait CleartextCreationEngine<Raw, Cleartext>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Creates a cleartext from a raw value.
    fn create_cleartext(
        &mut self,
        raw: &Raw,
    ) -> Result<Cleartext, CleartextCreationError<Self::EngineError>>;

    /// Unsafely creates a cleartext from a raw value.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextCreationError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn create_cleartext_unchecked(&mut self, raw: &Raw) -> Cleartext;
}
