use super::engine_error;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity};
use concrete_commons::dispersion::Variance;

engine_error! {
    LweCiphertextInplaceEncryptionError for LweCiphertextInplaceEncryptionEngine @
    LweDimensionMismatch => "The secret key and ciphertext lwe dimensions must be the same."
}

/// A trait for engines encrypting (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` lwe ciphertext with the
/// encryption of the `input` plaintext, under the `key` secret key.
///
/// # Formal Definition
pub trait LweCiphertextInplaceEncryptionEngine<SecretKey, Plaintext, Ciphertext>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Plaintext: PlaintextEntity<Representation = SecretKey::Representation>,
    Ciphertext: LweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
{
    /// Encrypts an lwe ciphertext.
    fn inplace_encrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    ) -> Result<(), LweCiphertextInplaceEncryptionError<Self::EngineError>>;

    /// Unsafely encrypts an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceEncryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_encrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Ciphertext,
        input: &Plaintext,
        noise: Variance,
    );
}
