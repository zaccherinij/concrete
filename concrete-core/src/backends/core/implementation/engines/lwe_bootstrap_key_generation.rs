use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

use crate::backends::core::implementation::engines::CoreEngine;
use crate::backends::core::implementation::entities::{
    FourierLweBootstrapKey32, FourierLweBootstrapKey64, GlweSecretKey32, GlweSecretKey64,
    LweBootstrapKey32, LweBootstrapKey64, LweSecretKey32, LweSecretKey64,
};
use crate::backends::core::private::crypto::bootstrap::{
    FourierBootstrapKey as ImplFourierBootstrapKey,
    StandardBootstrapKey as ImplStandardBootstrapKey,
};
use crate::backends::core::private::math::fft::Complex64;
use crate::specification::engines::{
    LweBootstrapKeyGenerationEngine, LweBootstrapKeyGenerationError,
};

impl LweBootstrapKeyGenerationEngine<LweSecretKey32, GlweSecretKey32, LweBootstrapKey32>
    for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: LweBootstrapKey64 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk).unwrap();
    /// engine.destroy(glwe_sk).unwrap();
    /// engine.destroy(bsk).unwrap();
    /// ```
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey32, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 1 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > 32 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooLarge);
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey32 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey32(key)
    }
}

impl LweBootstrapKeyGenerationEngine<LweSecretKey64, GlweSecretKey64, LweBootstrapKey64>
    for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: LweBootstrapKey64 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk).unwrap();
    /// engine.destroy(glwe_sk).unwrap();
    /// engine.destroy(bsk).unwrap();
    /// ```
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<LweBootstrapKey64, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 1 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > 32 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooLarge);
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> LweBootstrapKey64 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        LweBootstrapKey64(key)
    }
}

impl LweBootstrapKeyGenerationEngine<LweSecretKey32, GlweSecretKey32, FourierLweBootstrapKey32>
    for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey32 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey32 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: FourierLweBootstrapKey32 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk).unwrap();
    /// engine.destroy(glwe_sk).unwrap();
    /// engine.destroy(bsk).unwrap();
    /// ```
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<FourierLweBootstrapKey32, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 1 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > 32 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooLarge);
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey32,
        output_key: &GlweSecretKey32,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> FourierLweBootstrapKey32 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        let mut fourier_key = ImplFourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        fourier_key.fill_with_forward_fourier(&key);
        FourierLweBootstrapKey32(fourier_key)
    }
}

impl LweBootstrapKeyGenerationEngine<LweSecretKey64, GlweSecretKey64, FourierLweBootstrapKey64>
    for CoreEngine
{
    /// # Example
    /// ```
    /// use concrete_commons::dispersion::Variance;
    /// use concrete_commons::parameters::{
    ///     DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    /// };
    /// use concrete_core::prelude::*;
    /// let mut engine = CoreEngine::new().unwrap();
    /// // DISCLAIMER: the parameters used here are only for test purpose, and not secure.
    /// let (lwe_dim, glwe_dim, poly_size) = (LweDimension(4), GlweDimension(6), PolynomialSize(256));
    /// let (dec_lc, dec_bl) = (DecompositionLevelCount(3), DecompositionBaseLog(5));
    /// let lwe_sk: LweSecretKey64 = engine.generate_lwe_secret_key(lwe_dim).unwrap();
    /// let glwe_sk: GlweSecretKey64 = engine
    ///     .generate_glwe_secret_key(glwe_dim, poly_size)
    ///     .unwrap();
    /// let noise = Variance(2_f64.powf(-25.));
    /// let bsk: FourierLweBootstrapKey64 = engine
    ///     .generate_lwe_bootstrap_key(&lwe_sk, &glwe_sk, dec_bl, dec_lc, noise)
    ///     .unwrap();
    /// assert_eq!(bsk.glwe_dimension(), glwe_dim);
    /// assert_eq!(bsk.polynomial_size(), poly_size);
    /// assert_eq!(bsk.input_lwe_dimension(), lwe_dim);
    /// assert_eq!(bsk.decomposition_base_log(), dec_bl);
    /// assert_eq!(bsk.decomposition_level_count(), dec_lc);
    /// engine.destroy(lwe_sk);
    /// engine.destroy(glwe_sk);
    /// engine.destroy(bsk);
    /// ```
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<FourierLweBootstrapKey64, LweBootstrapKeyGenerationError<Self::EngineError>> {
        if decomposition_base_log.0 == 0 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionBaseLog);
        }
        if decomposition_level_count.0 == 1 {
            return Err(LweBootstrapKeyGenerationError::NullDecompositionLevelCount);
        }
        if decomposition_base_log.0 * decomposition_level_count.0 > 32 {
            return Err(LweBootstrapKeyGenerationError::DecompositionTooLarge);
        }
        Ok(unsafe {
            self.generate_lwe_bootstrap_key_unchecked(
                input_key,
                output_key,
                decomposition_base_log,
                decomposition_level_count,
                noise,
            )
        })
    }

    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey64,
        output_key: &GlweSecretKey64,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> FourierLweBootstrapKey64 {
        let mut key = ImplStandardBootstrapKey::allocate(
            0,
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        key.fill_with_new_key(
            &input_key.0,
            &output_key.0,
            noise,
            &mut self.encryption_generator,
        );
        let mut fourier_key = ImplFourierBootstrapKey::allocate(
            Complex64::new(0., 0.),
            output_key.0.key_size().to_glwe_size(),
            output_key.0.polynomial_size(),
            decomposition_level_count,
            decomposition_base_log,
            input_key.0.key_size(),
        );
        fourier_key.fill_with_forward_fourier(&key);
        FourierLweBootstrapKey64(fourier_key)
    }
}
