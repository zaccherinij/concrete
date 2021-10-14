use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::CleartextEntity;

engine_error! {
    CleartextInplaceRetrievalError for CleartextInplaceRetrievalEngine @
}

/// A trait for engines retrieving (inplace) cleartexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` raw value with the
/// retrieval of the `input` cleartext value.
///
/// # Formal Definition
pub trait CleartextInplaceRetrievalEngine<Cleartext, Raw>: AbstractEngine
where
    Cleartext: CleartextEntity,
{
    /// Retrieves a raw value from a cleartext inplace.
    fn inplace_retrieve_cleartext(
        &mut self,
        output: &mut Raw,
        input: &Cleartext,
    ) -> Result<(), CleartextInplaceRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves a raw value from a cleartext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`CleartextInplaceRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn inplace_retrieve_cleartext_unchecked(&mut self, output: &mut Raw, input: &Cleartext);
}
