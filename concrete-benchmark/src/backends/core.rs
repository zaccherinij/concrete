//! A module benchmarking the `core` backend of the library.
use concrete_core::backends::core::implementation::engines::CoreEngine;
use concrete_core::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, CleartextVector32, CleartextVector64, FourierLweBootstrapKey32,
    FourierLweBootstrapKey64, GlweCiphertext32, GlweCiphertext64, GlweCiphertextVector32,
    GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64, LweBootstrapKey32, LweBootstrapKey64,
    LweCiphertext32, LweCiphertext64, LweCiphertextVector32, LweCiphertextVector64,
    LweKeyswitchKey32, LweKeyswitchKey64, LweSecretKey32, LweSecretKey64, Plaintext32, Plaintext64,
    PlaintextVector32, PlaintextVector64,
};
use criterion::Criterion;

#[rustfmt::skip]
pub fn bench() {
    use crate::generics::*;
    let mut criterion = Criterion::default().configure_from_args();
    cleartext_creation::bench::<CoreEngine, u32, Cleartext32>(&mut criterion);
    cleartext_creation::bench::<CoreEngine, u64, Cleartext64>(&mut criterion);
    cleartext_vector_creation::bench::<CoreEngine, u32, CleartextVector32>(&mut criterion);
    cleartext_vector_creation::bench::<CoreEngine, u64, CleartextVector64>(&mut criterion);
    glwe_ciphertext_decryption::bench::<CoreEngine, GlweSecretKey32, GlweCiphertext32, PlaintextVector32, CoreEngine>(&mut criterion);
    glwe_ciphertext_decryption::bench::<CoreEngine, GlweSecretKey64, GlweCiphertext64, PlaintextVector64, CoreEngine>(&mut criterion);
    glwe_ciphertext_encryption::bench::<CoreEngine, GlweSecretKey32, PlaintextVector32, GlweCiphertext32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_encryption::bench::<CoreEngine, GlweSecretKey64, PlaintextVector64, GlweCiphertext64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_inplace_decryption::bench::<CoreEngine, GlweSecretKey32,  GlweCiphertext32, PlaintextVector32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_inplace_decryption::bench::<CoreEngine, GlweSecretKey64,  GlweCiphertext64, PlaintextVector64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_inplace_encryption::bench::<CoreEngine, GlweSecretKey32, PlaintextVector32,  GlweCiphertext32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_inplace_encryption::bench::<CoreEngine, GlweSecretKey64, PlaintextVector64,  GlweCiphertext64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_vector_decryption::bench::<CoreEngine, GlweSecretKey32, GlweCiphertextVector32, PlaintextVector32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_vector_decryption::bench::<CoreEngine, GlweSecretKey64, GlweCiphertextVector64, PlaintextVector64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_vector_encryption::bench::<CoreEngine, GlweSecretKey32, PlaintextVector32, GlweCiphertextVector32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_vector_encryption::bench::<CoreEngine, GlweSecretKey64, PlaintextVector64, GlweCiphertextVector64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_vector_inplace_decryption::bench::<CoreEngine, GlweSecretKey32, GlweCiphertextVector32, PlaintextVector32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_vector_inplace_decryption::bench::<CoreEngine, GlweSecretKey64, GlweCiphertextVector64, PlaintextVector64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_vector_inplace_encryption::bench::<CoreEngine, GlweSecretKey32, PlaintextVector32, GlweCiphertextVector32, CoreEngine, u32>(&mut criterion);
    glwe_ciphertext_vector_inplace_encryption::bench::<CoreEngine, GlweSecretKey64, PlaintextVector64, GlweCiphertextVector64, CoreEngine, u64>(&mut criterion);
    glwe_ciphertext_vector_zero_encryption::bench::<CoreEngine, GlweSecretKey32, GlweCiphertextVector32, CoreEngine>(&mut criterion);
    glwe_ciphertext_vector_zero_encryption::bench::<CoreEngine, GlweSecretKey64, GlweCiphertextVector64, CoreEngine>(&mut criterion);
    glwe_ciphertext_zero_encryption::bench::<CoreEngine, GlweSecretKey32, GlweCiphertext32, CoreEngine>(&mut criterion);
    glwe_ciphertext_zero_encryption::bench::<CoreEngine, GlweSecretKey64, GlweCiphertext64, CoreEngine>(&mut criterion);
    glwe_secret_key_generation::bench::<CoreEngine, GlweSecretKey32>(&mut criterion);
    glwe_secret_key_generation::bench::<CoreEngine, GlweSecretKey64>(&mut criterion);
    lwe_bootstrap_key_conversion::bench::<CoreEngine, LweBootstrapKey32, FourierLweBootstrapKey32, CoreEngine, LweSecretKey32, GlweSecretKey32>(&mut criterion);
    lwe_bootstrap_key_conversion::bench::<CoreEngine, LweBootstrapKey64, FourierLweBootstrapKey64, CoreEngine, LweSecretKey64, GlweSecretKey64>(&mut criterion);
    lwe_bootstrap_key_generation::bench::<CoreEngine, LweSecretKey32, GlweSecretKey32, LweBootstrapKey32, CoreEngine>(&mut criterion);
    lwe_bootstrap_key_generation::bench::<CoreEngine, LweSecretKey64, GlweSecretKey64, LweBootstrapKey64, CoreEngine>(&mut criterion);
    lwe_ciphertext_assigned_addition::bench::<CoreEngine, LweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_assigned_addition::bench::<CoreEngine, LweCiphertext64, LweCiphertext64, CoreEngine, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_inplace_bootstrap::bench::<CoreEngine, FourierLweBootstrapKey32, GlweCiphertext32, LweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32, LweSecretKey32, GlweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_bootstrap::bench::<CoreEngine, FourierLweBootstrapKey64, GlweCiphertext64, LweCiphertext64, LweCiphertext64, CoreEngine, LweSecretKey64, LweSecretKey64, GlweSecretKey64>(&mut criterion);
    lwe_ciphertext_assigned_negation::bench::<CoreEngine, LweCiphertext32, CoreEngine, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_assigned_negation::bench::<CoreEngine, LweCiphertext64, CoreEngine, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_cleartext_assigned_multiplication::bench::<CoreEngine, LweCiphertext32, Cleartext32, CoreEngine, u32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_cleartext_assigned_multiplication::bench::<CoreEngine, LweCiphertext64, Cleartext64, CoreEngine, u64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_cleartext_inplace_multiplication::bench::<CoreEngine, LweCiphertext32, Cleartext32, LweCiphertext32, CoreEngine, u32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_cleartext_inplace_multiplication::bench::<CoreEngine, LweCiphertext64, Cleartext64, LweCiphertext64, CoreEngine, u64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_decryption::bench::<CoreEngine, LweSecretKey32, LweCiphertext32, Plaintext32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_decryption::bench::<CoreEngine, LweSecretKey64, LweCiphertext64, Plaintext64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_encryption::bench::<CoreEngine, LweSecretKey32, Plaintext32, LweCiphertext32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_encryption::bench::<CoreEngine, LweSecretKey64, Plaintext64, LweCiphertext64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_inplace_addition::bench::<CoreEngine, LweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_addition::bench::<CoreEngine, LweCiphertext64, LweCiphertext64, CoreEngine, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_inplace_affine_transformation::bench::<CoreEngine, LweCiphertextVector32, CleartextVector32, Plaintext32, LweCiphertext32, CoreEngine, u32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_affine_transformation::bench::<CoreEngine, LweCiphertextVector64, CleartextVector64, Plaintext64, LweCiphertext64, CoreEngine, u64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_inplace_decryption::bench::<CoreEngine, LweSecretKey32, LweCiphertext32, Plaintext32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_inplace_decryption::bench::<CoreEngine, LweSecretKey64, LweCiphertext64, Plaintext64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_inplace_encryption::bench::<CoreEngine, LweSecretKey32, Plaintext32, LweCiphertext32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_inplace_encryption::bench::<CoreEngine, LweSecretKey64, Plaintext64, LweCiphertext64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_inplace_extraction::bench::<CoreEngine, GlweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32, GlweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_keyswitch::bench::<CoreEngine, LweKeyswitchKey32, LweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_keyswitch::bench::<CoreEngine, LweKeyswitchKey64, LweCiphertext64, LweCiphertext64, CoreEngine, LweSecretKey64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_inplace_negation::bench::<CoreEngine, LweCiphertext32, LweCiphertext32, CoreEngine, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_inplace_negation::bench::<CoreEngine, LweCiphertext64, LweCiphertext64, CoreEngine, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_plaintext_assigned_addition::bench::<CoreEngine, LweCiphertext32, Plaintext32, CoreEngine, u32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_plaintext_assigned_addition::bench::<CoreEngine, LweCiphertext64, Plaintext64, CoreEngine, u64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_plaintext_inplace_addition::bench::<CoreEngine, LweCiphertext32, Plaintext32, LweCiphertext32, CoreEngine, u32, LweSecretKey32>(&mut criterion);
    lwe_ciphertext_plaintext_inplace_addition::bench::<CoreEngine, LweCiphertext64, Plaintext64, LweCiphertext64, CoreEngine, u64, LweSecretKey64>(&mut criterion);
    lwe_ciphertext_vector_decryption::bench::<CoreEngine, LweSecretKey32, LweCiphertextVector32, PlaintextVector32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_vector_decryption::bench::<CoreEngine, LweSecretKey64, LweCiphertextVector64, PlaintextVector64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_vector_encryption::bench::<CoreEngine, LweSecretKey32, PlaintextVector32, LweCiphertextVector32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_vector_encryption::bench::<CoreEngine, LweSecretKey64, PlaintextVector64, LweCiphertextVector64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_vector_inplace_decryption::bench::<CoreEngine, LweSecretKey32, LweCiphertextVector32, PlaintextVector32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_vector_inplace_decryption::bench::<CoreEngine, LweSecretKey64, LweCiphertextVector64, PlaintextVector64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_vector_inplace_encryption::bench::<CoreEngine, LweSecretKey32, PlaintextVector32, LweCiphertextVector32, CoreEngine, u32>(&mut criterion);
    lwe_ciphertext_vector_inplace_encryption::bench::<CoreEngine, LweSecretKey64, PlaintextVector64, LweCiphertextVector64, CoreEngine, u64>(&mut criterion);
    lwe_ciphertext_vector_zero_encryption::bench::<CoreEngine, LweSecretKey32, LweCiphertextVector32, CoreEngine>(&mut criterion);
    lwe_ciphertext_vector_zero_encryption::bench::<CoreEngine, LweSecretKey64, LweCiphertextVector64, CoreEngine>(&mut criterion);
    lwe_ciphertext_zero_encryption::bench::<CoreEngine, LweSecretKey32, LweCiphertext32, CoreEngine>(&mut criterion);
    lwe_ciphertext_zero_encryption::bench::<CoreEngine, LweSecretKey64, LweCiphertext64, CoreEngine>(&mut criterion);
    lwe_keyswitch_key_generation::bench::<CoreEngine, LweSecretKey32, LweSecretKey32, LweKeyswitchKey32, CoreEngine>(&mut criterion);
    lwe_keyswitch_key_generation::bench::<CoreEngine, LweSecretKey64, LweSecretKey64, LweKeyswitchKey64, CoreEngine>(&mut criterion);
    lwe_secret_key_generation::bench::<CoreEngine, LweSecretKey32>(&mut criterion);
    lwe_secret_key_generation::bench::<CoreEngine, LweSecretKey64>(&mut criterion);
    plaintext_creation::bench::<CoreEngine, u32, Plaintext32>(&mut criterion);
    plaintext_creation::bench::<CoreEngine, u64, Plaintext64>(&mut criterion);
    plaintext_vector_creation::bench::<CoreEngine, u32, PlaintextVector32>(&mut criterion);
    plaintext_vector_creation::bench::<CoreEngine, u64, PlaintextVector64>(&mut criterion);
}
