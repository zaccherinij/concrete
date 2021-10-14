use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::secret::GlweSecretKey as ImpGlweSecretKey;
use crate::specification::entities::markers::{BinaryKeyFlavor, GlweSecretKeyKind};
use crate::specification::entities::{AbstractEntity, GlweSecretKeyEntity};
use concrete_commons::key_kinds::BinaryKeyKind;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

#[derive(Debug, Clone, PartialEq)]
pub struct GlweSecretKey32(pub(crate) ImpGlweSecretKey<BinaryKeyKind, Vec<u32>>);
impl AbstractEntity for GlweSecretKey32 {
    type Kind = GlweSecretKeyKind;
    type Representation = CpuStandard32;
}
impl GlweSecretKeyEntity for GlweSecretKey32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlweSecretKey64(pub(crate) ImpGlweSecretKey<BinaryKeyKind, Vec<u64>>);
impl AbstractEntity for GlweSecretKey64 {
    type Kind = GlweSecretKeyKind;
    type Representation = CpuStandard64;
}
impl GlweSecretKeyEntity for GlweSecretKey64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.key_size()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
