use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{GlweCiphertextEntity, LweCiphertextEntity};
use concrete_commons::parameters::MonomialDegree;

engine_error! {
    LweCiphertextInplaceExtractionError for LweCiphertextInplaceExtractionEngine@
    SizeMismatch => "The sizes of the output lwe and the input glwe must be compatible.",
    MonomialDegreeTooLarge => "The monomial degree must be lower than the glwe polynomial size."
}

/// A trait for engines extracting (inplace) lwe ciphertext from glwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// sample extraction of the `nth` coefficients of the `input` glwe ciphertext.
///
/// # Formal definition
///
/// This operation is usually referred to as a _sample extract_ in the literature.
pub trait LweCiphertextInplaceExtractionEngine<GlweCiphertext, LweCiphertext>:
    AbstractEngine
where
    GlweCiphertext: GlweCiphertextEntity,
    LweCiphertext: LweCiphertextEntity<
        KeyFlavor = GlweCiphertext::KeyFlavor,
        Representation = GlweCiphertext::Representation,
    >,
{
    /// Extracts an lwe ciphertext from a glwe ciphertext.
    fn inplace_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext,
        input: &GlweCiphertext,
        nth: MonomialDegree,
    ) -> Result<(), LweCiphertextInplaceExtractionError<Self::EngineError>>;

    /// Unsafely extracts an lwe ciphertext from a glwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceExtractionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext,
        input: &GlweCiphertext,
        nth: MonomialDegree,
    );
}
