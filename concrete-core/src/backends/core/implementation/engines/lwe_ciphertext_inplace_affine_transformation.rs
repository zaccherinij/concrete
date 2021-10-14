use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    CleartextVector32, CleartextVector64, LweCiphertext32, LweCiphertext64, LweCiphertextVector32,
    LweCiphertextVector64, Plaintext32, Plaintext64,
};
use crate::specification::engines::{
    LweCiphertextInplaceAffineTransformationEngine, LweCiphertextInplaceAffineTransformationError,
};
use crate::specification::entities::{
    CleartextVectorEntity, LweCiphertextEntity, LweCiphertextVectorEntity,
};

impl
    LweCiphertextInplaceAffineTransformationEngine<
        LweCiphertextVector32,
        CleartextVector32,
        Plaintext32,
        LweCiphertext32,
    > for CoreEngine
{
    fn inplace_affine_transform_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) -> Result<(), LweCiphertextInplaceAffineTransformationError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweCiphertextInplaceAffineTransformationError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweCiphertextInplaceAffineTransformationError::CleartextCountMismatch);
        }
        unsafe {
            self.inplace_affine_transform_lwe_ciphertext_unchecked(output, inputs, weights, bias)
        };
        Ok(())
    }

    unsafe fn inplace_affine_transform_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        inputs: &LweCiphertextVector32,
        weights: &CleartextVector32,
        bias: &Plaintext32,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}

impl
    LweCiphertextInplaceAffineTransformationEngine<
        LweCiphertextVector64,
        CleartextVector64,
        Plaintext64,
        LweCiphertext64,
    > for CoreEngine
{
    fn inplace_affine_transform_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) -> Result<(), LweCiphertextInplaceAffineTransformationError<Self::EngineError>> {
        if output.lwe_dimension() != inputs.lwe_dimension() {
            return Err(LweCiphertextInplaceAffineTransformationError::LweDimensionMismatch);
        }
        if inputs.lwe_ciphertext_count().0 != weights.cleartext_count().0 {
            return Err(LweCiphertextInplaceAffineTransformationError::CleartextCountMismatch);
        }
        unsafe {
            self.inplace_affine_transform_lwe_ciphertext_unchecked(output, inputs, weights, bias)
        };
        Ok(())
    }

    unsafe fn inplace_affine_transform_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        inputs: &LweCiphertextVector64,
        weights: &CleartextVector64,
        bias: &Plaintext64,
    ) {
        output
            .0
            .fill_with_multisum_with_bias(&inputs.0, &weights.0, &bias.0);
    }
}
