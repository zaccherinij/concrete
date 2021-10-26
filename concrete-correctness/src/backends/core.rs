use crate::generics::*;
use crate::utils::instantiate_test;
use concrete_core::backends::core::implementation::engines::CoreEngine;
use concrete_core::backends::core::implementation::entities::{
    Cleartext32, Cleartext64, CleartextVector32, CleartextVector64, GlweCiphertext32,
    GlweCiphertext64, GlweSecretKey32, GlweSecretKey64, PlaintextVector32, PlaintextVector64,
};

instantiate_test!(cleartext_creation => CoreEngine, u32, Cleartext32, CoreEngine);
instantiate_test!(cleartext_creation => CoreEngine, u64, Cleartext64, CoreEngine);
instantiate_test!(cleartext_vector_creation => CoreEngine, u32, CleartextVector32, CoreEngine);
instantiate_test!(cleartext_vector_creation => CoreEngine, u64, CleartextVector64, CoreEngine);
instantiate_test!(glwe_ciphertext_decryption => CoreEngine, GlweSecretKey32, GlweCiphertext32, PlaintextVector32, CoreEngine, u32);
instantiate_test!(glwe_ciphertext_decryption => CoreEngine, GlweSecretKey64, GlweCiphertext64, PlaintextVector64, CoreEngine, u64);
