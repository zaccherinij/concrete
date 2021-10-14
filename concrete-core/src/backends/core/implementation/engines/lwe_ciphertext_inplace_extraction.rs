use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    GlweCiphertext32, GlweCiphertext64, LweCiphertext32, LweCiphertext64,
};
use crate::specification::engines::{
    LweCiphertextInplaceExtractionEngine, LweCiphertextInplaceExtractionError,
};
use crate::specification::entities::GlweCiphertextEntity;
use concrete_commons::parameters::MonomialDegree;

impl LweCiphertextInplaceExtractionEngine<GlweCiphertext32, LweCiphertext32> for CoreEngine {
    fn inplace_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialDegree,
    ) -> Result<(), LweCiphertextInplaceExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(LweCiphertextInplaceExtractionError::SizeMismatch);
        }
        if nth.0 > input.glwe_dimension().0 - 1 {
            return Err(LweCiphertextInplaceExtractionError::MonomialDegreeTooLarge);
        }
        unsafe { self.inplace_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn inplace_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext32,
        input: &GlweCiphertext32,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}

impl LweCiphertextInplaceExtractionEngine<GlweCiphertext64, LweCiphertext64> for CoreEngine {
    fn inplace_extract_lwe_ciphertext(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialDegree,
    ) -> Result<(), LweCiphertextInplaceExtractionError<Self::EngineError>> {
        if output.0.lwe_size().to_lwe_dimension().0
            != input.0.polynomial_size().0 * input.0.size().to_glwe_dimension().0
        {
            return Err(LweCiphertextInplaceExtractionError::SizeMismatch);
        }
        if nth.0 > input.glwe_dimension().0 - 1 {
            return Err(LweCiphertextInplaceExtractionError::MonomialDegreeTooLarge);
        }
        unsafe { self.inplace_extract_lwe_ciphertext_unchecked(output, input, nth) };
        Ok(())
    }

    unsafe fn inplace_extract_lwe_ciphertext_unchecked(
        &mut self,
        output: &mut LweCiphertext64,
        input: &GlweCiphertext64,
        nth: MonomialDegree,
    ) {
        output.0.fill_with_glwe_sample_extraction(&input.0, nth);
    }
}
