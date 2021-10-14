/// This trait is necessary to write generic tests which can create plaintext and ciphertexts.
///
/// For any type, it makes it possible to create a value (calling `any`), or a vector of values
/// (calling `any_vec`). The value itself is not important.
pub trait RawNumeric: Sized {
    fn any() -> Self;
    fn any_vec(size: usize) -> Vec<Self>;
}

impl RawNumeric for u32 {
    fn any() -> Self {
        1u32
    }

    fn any_vec(size: usize) -> Vec<Self> {
        vec![1u32; size]
    }
}

impl RawNumeric for u64 {
    fn any() -> Self {
        1u64
    }

    fn any_vec(size: usize) -> Vec<Self> {
        vec![1u64; size]
    }
}
