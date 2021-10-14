use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::lwe::LweKeyswitchKey as ImplLweKeyswitchKey;
use crate::specification::entities::markers::{BinaryKeyFlavor, LweKeyswitchKeyKind};
use crate::specification::entities::{AbstractEntity, LweKeyswitchKeyEntity};
use concrete_commons::parameters::{DecompositionBaseLog, DecompositionLevelCount, LweDimension};

#[derive(Debug, Clone, PartialEq)]
pub struct LweKeyswitchKey32(pub(crate) ImplLweKeyswitchKey<Vec<u32>>);
impl AbstractEntity for LweKeyswitchKey32 {
    type Kind = LweKeyswitchKeyKind;
    type Representation = CpuStandard32;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKey32 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LweKeyswitchKey64(pub(crate) ImplLweKeyswitchKey<Vec<u64>>);
impl AbstractEntity for LweKeyswitchKey64 {
    type Kind = LweKeyswitchKeyKind;
    type Representation = CpuStandard64;
}
impl LweKeyswitchKeyEntity for LweKeyswitchKey64 {
    type InputKeyFlavor = BinaryKeyFlavor;
    type OutputKeyFlavor = BinaryKeyFlavor;

    fn input_lwe_dimension(&self) -> LweDimension {
        self.0.before_key_size()
    }

    fn output_lwe_dimension(&self) -> LweDimension {
        self.0.after_key_size()
    }

    fn decomposition_level_count(&self) -> DecompositionLevelCount {
        self.0.decomposition_levels_count()
    }

    fn decomposition_base_log(&self) -> DecompositionBaseLog {
        self.0.decomposition_base_log()
    }
}
