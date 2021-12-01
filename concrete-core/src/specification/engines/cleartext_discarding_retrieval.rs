use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextEntity;

engine_error! {
    CleartextDiscardingRetrievalError for CleartextDiscardingRetrievalEngine @
}

/// A trait for engines retrieving (discarding) arbitrary values from cleartexts .
///
/// # Semantics
///
/// This [discarding](super#operation-semantics) operation fills the `value` arbitrary value with the
/// retrieval of the `input` cleartext.
///
/// # Formal Definition
pub trait CleartextDiscardingRetrievalEngine<Cleartext, Value>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Retrieves an arbitrary value from a cleartext.
    fn discarding_retrieve_cleartext(
        &mut self,
        value: &mut Value,
        input: &Cleartext,
    ) -> Result<(), CleartextDiscardingRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves an arbitrary value from a cleartext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextDiscardingRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn discarding_retrieve_cleartext_unchecked(
        &mut self,
        value: &mut Value,
        input: &Cleartext,
    );
}
