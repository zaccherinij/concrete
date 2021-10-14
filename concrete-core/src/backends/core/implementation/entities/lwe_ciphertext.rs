use super::super::super::private::crypto::lwe::LweCiphertext as ImplLweCiphertext;
use crate::backends::core::implementation::entities::markers::{CpuStandard32, CpuStandard64};
use crate::specification::entities::markers::{BinaryKeyFlavor, LweCiphertextKind};
use crate::specification::entities::{AbstractEntity, LweCiphertextEntity};
use concrete_commons::parameters::LweDimension;

/// An owned lwe ciphertext in the cpu memory, in the standard domain, using 32-bits precision
/// integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertext32(pub(crate) ImplLweCiphertext<Vec<u32>>);
impl AbstractEntity for LweCiphertext32 {
    type Kind = LweCiphertextKind;
    type Representation = CpuStandard32;
}
impl LweCiphertextEntity for LweCiphertext32 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}

/// An owned lwe ciphertext in the cpu memory, in the standard domain, using 64-bits precision
/// integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LweCiphertext64(pub(crate) ImplLweCiphertext<Vec<u64>>);
impl AbstractEntity for LweCiphertext64 {
    type Kind = LweCiphertextKind;
    type Representation = CpuStandard64;
}
impl LweCiphertextEntity for LweCiphertext64 {
    type KeyFlavor = BinaryKeyFlavor;

    fn lwe_dimension(&self) -> LweDimension {
        self.0.lwe_size().to_lwe_dimension()
    }
}
