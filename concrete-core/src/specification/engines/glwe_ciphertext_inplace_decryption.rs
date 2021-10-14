use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

engine_error! {
    GlweCiphertextInplaceDecryptionError for GlweCiphertextInplaceDecryptionEngine@
    GlweDimensionMismatch => "The glwe dimension of the key and ciphertext must be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and ciphertext must be the same.",
    PlaintextCountMismatch => "The size of the output plaintext vector and the input ciphertext \
                               (polynomial size) must be the same."
}

/// A trait for engines decrypting (inplace) glwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext vector with the
/// decryption of the `input` glwe ciphertext, under the `key` secret key.
///
/// # Formal Definition
pub trait GlweCiphertextInplaceDecryptionEngine<SecretKey, Ciphertext, PlaintextVector>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    Ciphertext: GlweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
{
    /// Decrypts a glwe ciphertext inplace.
    fn inplace_decrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &Ciphertext,
    ) -> Result<(), GlweCiphertextInplaceDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts a glwe ciphertext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextInplaceDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_decrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut PlaintextVector,
        input: &Ciphertext,
    );
}
