use super::super::super::private::crypto::encoding::PlaintextList as CorePlaintextList;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::PlaintextVectorKind;
use crate::specification::entities::{AbstractEntity, PlaintextVectorEntity};
use concrete_commons::parameters::PlaintextCount;

/// A structure representing a vector of plaintexts in 32 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct PlaintextVector32(pub(crate) CorePlaintextList<Vec<u32>>);
impl AbstractEntity for PlaintextVector32 {
    type Kind = PlaintextVectorKind;
    type Representation = CpuStandard32;
}
impl PlaintextVectorEntity for PlaintextVector32 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}

/// A structure representing a vector of plaintexts in 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct PlaintextVector64(pub(crate) CorePlaintextList<Vec<u64>>);
impl AbstractEntity for PlaintextVector64 {
    type Kind = PlaintextVectorKind;
    type Representation = CpuStandard64;
}
impl PlaintextVectorEntity for PlaintextVector64 {
    fn plaintext_count(&self) -> PlaintextCount {
        self.0.count()
    }
}
