use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::PlaintextEntity;

engine_error! {
    PlaintextInplaceRetrievalError for PlaintextInplaceRetrievalEngine @
}

/// A trait for engines retrieving (inplace) plaintexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` raw value with the
/// retrieval of the `input` plaintext value.
///
/// # Formal Definition
pub trait PlaintextInplaceRetrievalEngine<Plaintext, Raw>: AbstractEngine
where
    Plaintext: PlaintextEntity,
{
    /// Retrieves a raw value from a plaintext inplace.
    fn inplace_retrieve_plaintext(
        &mut self,
        output: &mut Raw,
        input: &Plaintext,
    ) -> Result<(), PlaintextInplaceRetrievalError<Self::EngineError>>;

    /// Unsafely retrieves a raw value from a plaintext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`PlaintextInplaceRetrievalError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn inplace_retrieve_plaintext_unchecked(&mut self, output: &mut Raw, input: &Plaintext);
}
