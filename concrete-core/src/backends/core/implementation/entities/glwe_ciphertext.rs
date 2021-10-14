use super::super::super::private::crypto::glwe::GlweCiphertext as ImplGlweCiphertext;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::{BinaryKeyFlavor, GlweCiphertextKind};
use crate::specification::entities::{AbstractEntity, GlweCiphertextEntity};
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

#[derive(Debug, Clone, PartialEq)]
pub struct GlweCiphertext32(pub(crate) ImplGlweCiphertext<Vec<u32>>);
impl AbstractEntity for GlweCiphertext32 {
    type Kind = GlweCiphertextKind;
    type Representation = CpuStandard32;
}
impl GlweCiphertextEntity for GlweCiphertext32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlweCiphertext64(pub(crate) ImplGlweCiphertext<Vec<u64>>);
impl AbstractEntity for GlweCiphertext64 {
    type Kind = GlweCiphertextKind;
    type Representation = CpuStandard64;
}
impl GlweCiphertextEntity for GlweCiphertext64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.size().to_glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }
}
