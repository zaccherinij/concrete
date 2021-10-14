use super::super::super::private::crypto::glwe::GlweList as ImplGlweList;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::{BinaryKeyFlavor, GlweCiphertextVectorKind};
use crate::specification::entities::{AbstractEntity, GlweCiphertextVectorEntity};
use concrete_commons::parameters::{GlweCiphertextCount, GlweDimension, PolynomialSize};

#[derive(Debug, Clone, PartialEq)]
pub struct GlweCiphertextVector32(pub(crate) ImplGlweList<Vec<u32>>);
impl AbstractEntity for GlweCiphertextVector32 {
    type Kind = GlweCiphertextVectorKind;
    type Representation = CpuStandard32;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct GlweCiphertextVector64(pub(crate) ImplGlweList<Vec<u64>>);
impl AbstractEntity for GlweCiphertextVector64 {
    type Kind = GlweCiphertextVectorKind;
    type Representation = CpuStandard64;
}
impl GlweCiphertextVectorEntity for GlweCiphertextVector64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn glwe_dimension(&self) -> GlweDimension {
        self.0.glwe_dimension()
    }

    fn polynomial_size(&self) -> PolynomialSize {
        self.0.polynomial_size()
    }

    fn glwe_ciphertext_count(&self) -> GlweCiphertextCount {
        GlweCiphertextCount(self.0.ciphertext_count().0)
    }
}
