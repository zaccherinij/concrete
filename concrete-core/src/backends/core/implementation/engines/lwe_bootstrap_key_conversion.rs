use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, LweBootstrapKey32, LweBootstrapKey64,
};
use crate::backends::core::private::crypto::bootstrap::FourierBootstrapKey as ImplFourierBootstrapKey;
use crate::backends::core::private::math::fft::Complex64;
use crate::specification::engines::{
    LweBootstrapKeyConversionEngine, LweBootstrapKeyConversionError,
};
use crate::specification::entities::LweBootstrapKeyEntity;

impl LweBootstrapKeyConversionEngine<LweBootstrapKey32, FourierLweBootstrapKey32> for CoreEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     ?;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: LweBootstrapKey32 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     ?;
    /// let fourier_bsk: FourierLweBootstrapKey32 = engine.convert_lwe_bootstrap_key(&bsk)?;
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk)?;
    /// engine.destroy(glwe_sk)?;
    /// engine.destroy(bsk)?;
    /// engine.destroy(fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> Result<FourierLweBootstrapKey32, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey32,
    ) -> FourierLweBootstrapKey32 {
        let mut output = ImplFourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        output.fill_with_forward_fourier(&input.0);
        FourierLweBootstrapKey32(output)
    }
}

impl LweBootstrapKeyConversionEngine<LweBootstrapKey64, FourierLweBootstrapKey64> for CoreEngine {
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// # use std::error::Error;
    /// #
    /// # fn main() -> Result<(), Box<dyn Error>> {
    /// let mut engine = CoreEngine::new()?;
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim)?;
    /// let glwe_sk: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     ?;
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: LweBootstrapKey64 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     ?;
    /// let fourier_bsk: FourierLweBootstrapKey64 = engine.convert_lwe_bootstrap_key(&bsk)?;
    /// assert_eq!(fourier_bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(fourier_bsk.polynomial_size(), poly_size);
    /// assert_eq!(fourier_bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(fourier_bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(fourier_bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk)?;
    /// engine.destroy(glwe_sk)?;
    /// engine.destroy(bsk)?;
    /// engine.destroy(fourier_bsk)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> Result<FourierLweBootstrapKey64, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(
        &mut self,
        input: &LweBootstrapKey64,
    ) -> FourierLweBootstrapKey64 {
        let mut output = ImplFourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            input.glwe_dimension().to_glwe_size(),
            input.polynomial_size(),
            input.decomposition_level_count(),
            input.decomposition_base_log(),
            input.input_lwe_dimension(),
        );
        output.fill_with_forward_fourier(&input.0);
        FourierLweBootstrapKey64(output)
    }
}

impl<Key> LweBootstrapKeyConversionEngine<Key, Key> for CoreEngine
where
    Key: LweBootstrapKeyEntity + Clone,
{
    fn convert_lwe_bootstrap_key(
        &mut self,
        input: &Key,
    ) -> Result<Key, LweBootstrapKeyConversionError<Self::EngineError>> {
        Ok(unsafe { self.convert_lwe_bootstrap_key_unchecked(input) })
    }

    unsafe fn convert_lwe_bootstrap_key_unchecked(&mut self, input: &Key) -> Key {
        (*input).clone()
    }
}
