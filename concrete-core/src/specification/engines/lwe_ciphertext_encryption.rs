use super::engine_error;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweCiphertextEncryptionError for LweCiphertextEncryptionEngine @
}

/// A trait for engines encrypting lwe ciphertexts.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an lwe ciphertext containing the
/// encryption of the `input` plaintext under the `key` secret key.
///
/// # Formal Definition
pub trait LweCiphertextEncryptionEngine<SecretKey, Plaintext, Ciphertext>: AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity<Representation = SecretKey::Representation>,
    Ciphertext: LweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
{
    /// Encrypts an lwe ciphertext.
    fn encrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<Ciphertext, LweCiphertextEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextEncryptionError`]. For safety concerns _specific_ to an
    /// engine, refer to the implementer safety section.
    unsafe fn encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        input: &Plaintext,
        noise: Variance,
    ) -> Ciphertext;
}
