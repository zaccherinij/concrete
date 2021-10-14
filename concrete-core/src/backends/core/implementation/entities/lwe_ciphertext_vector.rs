use super::super::super::private::crypto::lwe::LweList as ImplLweList;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::{BinaryKeyFlavor, LweCiphertextVectorKind};
use crate::specification::entities::{AbstractEntity, LweCiphertextVectorEntity};
use concrete_commons::parameters::{LweCiphertextCount, LweDimension};

/// A vector of lwe ciphertexts in the cpu memory, in the standard domain, using 32-bits precision
/// integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextVector32(pub(crate) ImplLweList<Vec<u32>>);
impl AbstractEntity for LweCiphertextVector32 {
    type Kind = LweCiphertextVectorKind;
    type Representation = CpuStandard32;
}
impl LweCiphertextVectorEntity for LweCiphertextVector32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}

/// A vector of lwe ciphertexts in the cpu memory, in the standard domain, using 64-bits precision
/// integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertextVector64(pub(crate) ImplLweList<Vec<u64>>);
impl AbstractEntity for LweCiphertextVector64 {
    type Kind = LweCiphertextVectorKind;
    type Representation = CpuStandard64;
}
impl LweCiphertextVectorEntity for LweCiphertextVector64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }

    fn lwe_ciphertext_count(&self) -> LweCiphertextCount {
        LweCiphertextCount(self.0.count().0)
    }
}
