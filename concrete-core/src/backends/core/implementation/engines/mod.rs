//! This module implements all the operations
//! provided by the Core Engine.
use crate::backends::core::private::crypto::secret::generators::{
    EncryptionRandomGenerator as ImplEncryptionRandomGenerator,
    SecretRandomGenerator as ImplSecretRandomGenerator,
};
use crate::specification::engines::sealed::AbstractEngineSeal;
use crate::specification::engines::AbstractEngine;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// The error which can occur in the execution of FHE operations, due to the core implementation.
///
/// # Note:
///
/// There is currently no such case, as the core implementation is not expected to undergo some
/// major issues unrelated to FHE.
#[derive(Debug)]
pub enum CoreError {}
impl Display for CoreError {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        unreachable!()
    }
}
impl Error for CoreError {}

/// The main engine exposed by the core backend.
pub struct CoreEngine {
    secret_generator: ImplSecretRandomGenerator,
    encryption_generator: ImplEncryptionRandomGenerator,
}

impl AbstractEngineSeal for CoreEngine {}
impl AbstractEngine for CoreEngine {
    type EngineError = CoreError;

    fn new() -> Result<Self, Self::EngineError> {
        Ok(CoreEngine {
            secret_generator: ImplSecretRandomGenerator::new(None),
            encryption_generator: ImplEncryptionRandomGenerator::new(None),
        })
    }
}

mod cleartext_creation;
mod cleartext_inplace_retrieval;
mod cleartext_retrieval;
mod cleartext_vector_creation;
mod cleartext_vector_inplace_retrieval;
mod cleartext_vector_retrieval;
mod destruction;
mod glwe_ciphertext_decryption;
mod glwe_ciphertext_encryption;
mod glwe_ciphertext_inplace_decryption;
mod glwe_ciphertext_inplace_encryption;
mod glwe_ciphertext_vector_decryption;
mod glwe_ciphertext_vector_encryption;
mod glwe_ciphertext_vector_inplace_decryption;
mod glwe_ciphertext_vector_inplace_encryption;
mod glwe_ciphertext_vector_zero_encryption;
mod glwe_ciphertext_zero_encryption;
mod glwe_secret_key_generation;
mod lwe_bootstrap_key_conversion;
mod lwe_bootstrap_key_generation;
mod lwe_ciphertext_assigned_addition;
mod lwe_ciphertext_assigned_negation;
mod lwe_ciphertext_cleartext_assigned_multiplication;
mod lwe_ciphertext_cleartext_inplace_multiplication;
mod lwe_ciphertext_decryption;
mod lwe_ciphertext_encryption;
mod lwe_ciphertext_inplace_addition;
mod lwe_ciphertext_inplace_affine_transformation;
mod lwe_ciphertext_inplace_bootstrap;
mod lwe_ciphertext_inplace_decryption;
mod lwe_ciphertext_inplace_encryption;
mod lwe_ciphertext_inplace_extraction;
mod lwe_ciphertext_inplace_keyswitch;
mod lwe_ciphertext_inplace_negation;
mod lwe_ciphertext_plaintext_assigned_addition;
mod lwe_ciphertext_plaintext_inplace_addition;
mod lwe_ciphertext_vector_decryption;
mod lwe_ciphertext_vector_encryption;
mod lwe_ciphertext_vector_inplace_decryption;
mod lwe_ciphertext_vector_inplace_encryption;
mod lwe_ciphertext_vector_zero_encryption;
mod lwe_ciphertext_zero_encryption;
mod lwe_keyswitch_key_generation;
mod lwe_secret_key_generation;
mod plaintext_creation;
mod plaintext_inplace_retrieval;
mod plaintext_retrieval;
mod plaintext_vector_creation;
mod plaintext_vector_inplace_retrieval;
mod plaintext_vector_retrieval;
