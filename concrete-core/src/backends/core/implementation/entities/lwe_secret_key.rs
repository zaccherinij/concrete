use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::secret::LweSecretKey as ImpLweSecretKey;
use crate::specification::entities::markers::{BinaryKeyFlavor, LweSecretKeyKind};
use crate::specification::entities::{AbstractEntity, LweSecretKeyEntity};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::LweDimension;

#[derive(Debug, Clone, PartialEq)]
pub struct LweSecretKey32(pub(crate) ImpLweSecretKey<BinaryKeyKind, Vec<u32>>);
impl AbstractEntity for LweSecretKey32 {
    type Kind = LweSecretKeyKind;
    type Representation = CpuStandard32;
}
impl LweSecretKeyEntity for LweSecretKey32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LweSecretKey64(pub(crate) ImpLweSecretKey<BinaryKeyKind, Vec<u64>>);
impl AbstractEntity for LweSecretKey64 {
    type Kind = LweSecretKeyKind;
    type Representation = CpuStandard64;
}
impl LweSecretKeyEntity for LweSecretKey64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.key_size()
    }
}
