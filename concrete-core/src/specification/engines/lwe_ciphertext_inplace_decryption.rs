use super::engine_error;

use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{LweCiphertextEntity, LweSecretKeyEntity, PlaintextEntity};

engine_error! {
    LweCiphertextInplaceDecryptionError for LweCiphertextInplaceDecryptionEngine @
    LweDimensionMismatch => "The secret key and ciphertext lwe dimensions must be the same."
}

/// A trait for engines decrypting (inplace) lwe ciphertexts.
///
/// # Semantics
///
/// This [inplace](super#operation-semantics) operation fills the `output` plaintext with the
/// decryption of the `input` lwe ciphertext, under the `key` secret key.
///
/// # Formal Definition
pub trait LweCiphertextInplaceDecryptionEngine<SecretKey, Ciphertext, Plaintext>:
    AbstractEngine
where
    SecretKey: LweSecretKeyEntity,
    Ciphertext: LweCiphertextEntity<
        Representation = SecretKey::Representation,
        KeyFlavor = SecretKey::KeyFlavor,
    >,
    Plaintext: PlaintextEntity<Representation = SecretKey::Representation>,
{
    /// Decrypts an lwe ciphertext.
    fn inplace_decrypt_lwe_ciphertext(
        &mut self,
        key: &SecretKey,
        output: &mut Plaintext,
        input: &Ciphertext,
    ) -> Result<(), LweCiphertextInplaceDecryptionError<Self::EngineError>>;

    /// Unsafely decrypts an lwe ciphertext.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweCiphertextInplaceDecryptionError`]. For safety concerns _specific_ to an engine,
    /// refer to the implementer safety section.
    unsafe fn inplace_decrypt_lwe_ciphertext_unchecked(
        &mut self,
        key: &SecretKey,
        output: &mut Plaintext,
        input: &Ciphertext,
    );
}
