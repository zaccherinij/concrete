use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweCiphertextEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

engine_error! {
    GlweCiphertextInplaceEncryptionError for GlweCiphertextInplaceEncryptionEngine@
    GlweDimensionMismatch => "The glwe dimension of the key and ciphertext must be the same.",
    PolynomialSizeMismatch => "The polynomial size of the key and ciphertext must be the same.",
    PlaintextCountMismatch => "The size of the input plaintext vector and the output ciphertext \
                               (polynomial size) must be the same."
}

/// A trait for engines encrypting (inplace) glwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` glwe ciphertext with the
/// encryption of the `input` plaintext vector, under the `key` secret key.
///
/// # Formal Definition
pub trait GlweCiphertextInplaceEncryptionEngine<SecretKey, PlaintextVector, Ciphertext>:
    AbstractEngine
where
    SecretKey: GlweSecretKeyEntity,
    PlaintextVector: PlaintextVectorEntity<Representation = SecretKey::Representation>,
    Ciphertext: GlweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
{
    /// Encrypts a glwe ciphertext inplace.
    fn inplace_encrypt_glwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &PlaintextVector,
        noise: Variance,
    ) -> Result<(), GlweCiphertextInplaceEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts a glwe ciphertext inplace.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`GlweCiphertextInplaceEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_encrypt_glwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &PlaintextVector,
        noise: Variance,
    );
}
