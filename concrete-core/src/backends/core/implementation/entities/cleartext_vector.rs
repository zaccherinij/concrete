use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::encoding::CleartextList as ImplCleartextList;
use crate::specification::entities::markers::CleartextVectorKind;
use crate::specification::entities::{AbstractEntity, CleartextVectorEntity};
use concrete_commons::parameters::CleartextCount;

/// A structure representing a vector of cleartexts in 32 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct CleartextVector32(pub(crate) ImplCleartextList<Vec<u32>>);
impl AbstractEntity for CleartextVector32 {
    type Kind = CleartextVectorKind;
    type Representation = CpuStandard32;
}
impl CleartextVectorEntity for CleartextVector32 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}

/// A structure representing a vector of cleartexts in 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct CleartextVector64(pub(crate) ImplCleartextList<Vec<u64>>);
impl AbstractEntity for CleartextVector64 {
    type Kind = CleartextVectorKind;
    type Representation = CpuStandard64;
}
impl CleartextVectorEntity for CleartextVector64 {
    fn cleartext_count(&self) -> CleartextCount {
        self.0.count()
    }
}
