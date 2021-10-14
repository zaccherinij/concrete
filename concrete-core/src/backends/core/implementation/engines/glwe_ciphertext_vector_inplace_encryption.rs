use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertextVector32, GlweCiphertextVector64, GlweSecretKey32, GlweSecretKey64,
    PlaintextVector32, PlaintextVector64,
};

use crate::specification::engines::{
    GlweCiphertextVectorInplaceEncryptionEngine, GlweCiphertextVectorInplaceEncryptionError,
};
use crate::specification::entities::{
    GlweCiphertextVectorEntity, GlweSecretKeyEntity, PlaintextVectorEntity,
};
use concrete_commons::dispersion::Variance;

impl
    GlweCiphertextVectorInplaceEncryptionEngine<
        GlweSecretKey32,
        PlaintextVector32,
        GlweCiphertextVector32,
    > for CoreEngine
{
    fn inplace_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey32,
        output: &mut GlweCiphertextVector32,
        input: &PlaintextVector32,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}

impl
    GlweCiphertextVectorInplaceEncryptionEngine<
        GlweSecretKey64,
        PlaintextVector64,
        GlweCiphertextVector64,
    > for CoreEngine
{
    fn inplace_encrypt_glwe_ciphertext_vector(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) -> Result<(), GlweCiphertextVectorInplaceEncryptionError<Self::EngineError>> {
        if key.glwe_dimension() != output.glwe_dimension() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::GlweDimensionMismatch);
        }
        if key.polynomial_size() != output.polynomial_size() {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PolynomialSizeMismatch);
        }
        if output.polynomial_size().0 * output.glwe_ciphertext_count().0
            != input.plaintext_count().0
        {
            return Err(GlweCiphertextVectorInplaceEncryptionError::PlaintextCountMismatch);
        }
        unsafe { self.inplace_encrypt_glwe_ciphertext_vector_unchecked(key, output, input, noise) };
        Ok(())
    }

    unsafe fn inplace_encrypt_glwe_ciphertext_vector_unchecked(
        &mut self,
        key: &GlweSecretKey64,
        output: &mut GlweCiphertextVector64,
        input: &PlaintextVector64,
        noise: Variance,
    ) {
        key.0.encrypt_glwe_list(
            &mut output.0,
            &input.0,
            noise,
            &mut self.encryption_generator,
        );
    }
}
