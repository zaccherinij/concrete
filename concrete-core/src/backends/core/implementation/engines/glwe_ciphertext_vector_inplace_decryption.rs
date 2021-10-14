use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};
use crate::specification::engines::{
    GlweCiphertextVectorInplaceDecryptionEngine, GlweCiphertextVectorInplaceDecryptionError,
};
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};

impl
    GlweCiphertextVectorInplaceDecryptionEngine<
        GlweSecretKey32,
        GlweCiphertextVector32,
        PlaintextVector32,
    > for CoreEngine
{
    fn inplace_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) -> Result<(), GlweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0 != (key.polynomial_size().0 * key.glwe_dimension().0) {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut PlaintextVector32,
        input: &GlweCiphertextVector32,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}

impl
    GlweCiphertextVectorInplaceDecryptionEngine<
        GlweSecretKey64,
        GlweCiphertextVector64,
        PlaintextVector64,
    > for CoreEngine
{
    fn inplace_decrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) -> Result<(), GlweCiphertextVectorInplaceDecryptionError<Self::EngineError>> {
        if key.glwe_dimension() != input.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != input.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PolynomialSizeMismatch);
        }
        if output.plaintext_count().0 != (key.polynomial_size().0 * key.glwe_dimension().0) {
            return Err(GlweCiphertextVectorInplaceDecryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_decrypt_glwe_ciphertext_vector_unchecked(key, output, input) };
        Ok(())
    }

    unsafe fn inplace_decrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut PlaintextVector64,
        input: &GlweCiphertextVector64,
    ) {
        key.0.decrypt_glwe_list(&mut output.0, &input.0);
    }
}
