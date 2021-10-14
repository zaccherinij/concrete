use super::engine_error;
use crate::specification::engines::AbstractEngine;
use crate::specification::entities::{
    GlweSecretKeyEntity, LweBootstrapKeyEntity, LweSecretKeyEntity,
};
use concrete_commons::dispersion::Variance;
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount};

engine_error! {
    LweBootstrapKeyGenerationError for LweBootstrapKeyGenerationEngine @
    NullDecompositionBaseLog => "The key decomposition base log must be greater than zero.",
    NullDecompositionLevelCount => "The key decomposition level count must be greater than zero.",
    DecompositionTooLarge => "The decomposition precision (base log * level count) must not exceed \
                              the precision of the ciphertext."
}

/// A trait for engines generating lwe bootstrap keys.
///
/// # Semantics
///
/// This [pure](super#operation-semantics) operation generates an lwe bootstrap key from the
/// `input_key` lwe secret key, and the `output_key` glwe secret key.
///
/// # Formal Definition
pub trait LweBootstrapKeyGenerationEngine<LweSecretKey, GlweSecretKey, BootstrapKey>:
    AbstractEngine
where
    BootstrapKey: LweBootstrapKeyEntity,
    LweSecretKey: LweSecretKeyEntity<KeyFlavor = BootstrapKey::InputKeyFlavor>,
    GlweSecretKey: GlweSecretKeyEntity<KeyFlavor = BootstrapKey::OutputKeyFlavor>,
{
    /// Generates an lwe bootstrap key.
    fn generate_lwe_bootstrap_key(
        &mut self,
        input_key: &LweSecretKey,
        output_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> Result<BootstrapKey, LweBootstrapKeyGenerationError<Self::EngineError>>;

    /// Unsafely generates an lwe bootstrap key.
    ///
    /// # Safety
    /// For the _general_ safety concerns regarding this operation, refer to the different variants
    /// of [`LweBootstrapKeyGenerationError`]. For safety concerns _specific_ to an engine, refer to
    /// the implementer safety section.
    unsafe fn generate_lwe_bootstrap_key_unchecked(
        &mut self,
        input_key: &LweSecretKey,
        output_key: &GlweSecretKey,
        decomposition_base_log: DecompositionBaseLog,
        decomposition_level_count: DecompositionLevelCount,
        noise: Variance,
    ) -> BootstrapKey;
}
