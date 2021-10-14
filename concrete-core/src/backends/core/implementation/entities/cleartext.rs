use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::backends::core::private::crypto::encoding::Cleartext as ImplCleartext;
use crate::specification::entities::markers::CleartextKind;
use crate::specification::entities::{AbstractEntity, CleartextEntity};

/// A structure representing a cleartext in 32 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct Cleartext32(pub(crate) ImplCleartext<u32>);
impl AbstractEntity for Cleartext32 {
    type Kind = CleartextKind;
    type Representation = CpuStandard32;
}
impl CleartextEntity for Cleartext32 {}

/// A structure representing a cleartext in 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct Cleartext64(pub(crate) ImplCleartext<u64>);
impl AbstractEntity for Cleartext64 {
    type Kind = CleartextKind;
    type Representation = CpuStandard64;
}
impl CleartextEntity for Cleartext64 {}
