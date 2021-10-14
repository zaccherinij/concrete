use super::super::super::private::crypto::encoding::Plaintext as CorePlaintext;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::PlaintextKind;
use crate::specification::entities::{AbstractEntity, PlaintextEntity};

/// A structure representing a plaintext in 32 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext32(pub(crate) CorePlaintext<u32>);
impl AbstractEntity for Plaintext32 {
    type Kind = PlaintextKind;
    type Representation = CpuStandard32;
}
impl PlaintextEntity for Plaintext32 {}

/// A structure representing a plaintext in 64 bits of precision.
#[derive(Debug, Clone, PartialEq)]
pub struct Plaintext64(pub(crate) CorePlaintext<u64>);
impl AbstractEntity for Plaintext64 {
    type Kind = PlaintextKind;
    type Representation = CpuStandard64;
}
impl PlaintextEntity for Plaintext64 {}
