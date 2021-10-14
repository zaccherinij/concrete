//! A module containing generic testing functions.
//!
//! Every submodule here is expected to contain a generic `test` function which can be instantiated
//! with different engine types to verify the correctness of an operation.

pub mod cleartext_creation;
pub mod cleartext_vector_creation;
pub mod glwe_ciphertext_decryption;
pub mod glwe_ciphertext_encryption;
pub mod glwe_ciphertext_inplace_decryption;
pub mod glwe_ciphertext_inplace_encryption;
pub mod glwe_ciphertext_vector_decryption;
pub mod glwe_ciphertext_vector_encryption;
pub mod glwe_ciphertext_vector_inplace_decryption;
pub mod glwe_ciphertext_vector_inplace_encryption;
pub mod glwe_ciphertext_vector_zero_encryption;
pub mod glwe_ciphertext_zero_encryption;
pub mod glwe_secret_key_generation;
pub mod lwe_bootstrap_key_conversion;
pub mod lwe_bootstrap_key_generation;
pub mod lwe_ciphertext_assigned_addition;
pub mod lwe_ciphertext_assigned_negation;
pub mod lwe_ciphertext_cleartext_assigned_multiplication;
pub mod lwe_ciphertext_cleartext_inplace_multiplication;
pub mod lwe_ciphertext_decryption;
pub mod lwe_ciphertext_encryption;
pub mod lwe_ciphertext_inplace_addition;
pub mod lwe_ciphertext_inplace_affine_transformation;
pub mod lwe_ciphertext_inplace_bootstrap;
pub mod lwe_ciphertext_inplace_decryption;
pub mod lwe_ciphertext_inplace_encryption;
pub mod lwe_ciphertext_inplace_extraction;
pub mod lwe_ciphertext_inplace_keyswitch;
pub mod lwe_ciphertext_inplace_negation;
pub mod lwe_ciphertext_plaintext_assigned_addition;
pub mod lwe_ciphertext_plaintext_inplace_addition;
pub mod lwe_ciphertext_vector_decryption;
pub mod lwe_ciphertext_vector_encryption;
pub mod lwe_ciphertext_vector_inplace_decryption;
pub mod lwe_ciphertext_vector_inplace_encryption;
pub mod lwe_ciphertext_vector_zero_encryption;
pub mod lwe_ciphertext_zero_encryption;
pub mod lwe_keyswitch_key_generation;
pub mod lwe_secret_key_generation;
pub mod plaintext_creation;
pub mod plaintext_vector_creation;
