use std::fmt::{Debug, Display};

/// This macro instantiate a generic test into a concrete one for a particular engine
/// implementation.
macro_rules! instantiate_test {
    ($module:ident => $($param: ident),+ ) => {
        paste::paste!{
            #[test]
            fn [<$module _ $($param:lower)_ + >](){
                $module::test::<$($param,)+>();
            }
        }
    };
}
use concrete_commons::dispersion::{DispersionParameter, Variance};
use concrete_core::backends::core::private::math::random::RandomGenerator;
pub(crate) use instantiate_test;

/// This trait is necessary to write generic tests which can create plaintext and ciphertexts.
pub trait RawUnsignedIntegers: Sized + PartialEq + Debug + Copy + Display {
    const BITS: usize;
    fn one() -> Self;
    fn one_vec(size: usize) -> Vec<Self>;
    fn uniform() -> Self;
    fn uniform_vec(size: usize) -> Vec<Self>;
    fn into_f64(self) -> f64;
    fn modular_distance(first: Self, other: Self) -> Self;
}

impl RawUnsignedIntegers for u32 {
    const BITS: usize = 32;
    fn one() -> Self {
        1u32
    }
    fn one_vec(size: usize) -> Vec<Self> {
        vec![1u32; size]
    }
    fn uniform() -> Self {
        let mut generator = RandomGenerator::new(None);
        generator.random_uniform()
    }
    fn uniform_vec(size: usize) -> Vec<Self> {
        let mut generator = RandomGenerator::new(None);
        generator.random_uniform_tensor(size).into_container()
    }
    fn into_f64(self) -> f64 {
        self as f64
    }
    fn modular_distance(first: Self, other: Self) -> Self {
        let d0 = first.wrapping_sub(other);
        let d1 = other.wrapping_sub(first);
        std::cmp::min(d0, d1)
    }
}

impl RawUnsignedIntegers for u64 {
    const BITS: usize = 64;
    fn one() -> Self {
        1u64
    }
    fn one_vec(size: usize) -> Vec<Self> {
        vec![1u64; size]
    }
    fn uniform() -> Self {
        let mut generator = RandomGenerator::new(None);
        generator.random_uniform()
    }
    fn uniform_vec(size: usize) -> Vec<Self> {
        let mut generator = RandomGenerator::new(None);
        generator.random_uniform_tensor(size).into_container()
    }
    fn into_f64(self) -> f64 {
        self as f64
    }
    fn modular_distance(first: Self, other: Self) -> Self {
        let d0 = first.wrapping_sub(other);
        let d1 = other.wrapping_sub(first);
        std::cmp::min(d0, d1)
    }
}

pub fn assert_delta_std_dev<Raw>(first: &[Raw], second: &[Raw], dist: Variance)
where
    Raw: RawUnsignedIntegers,
{
    for (x, y) in first.iter().zip(second.iter()) {
        let distance: f64 = Raw::modular_distance(*x, *y).into_f64();
        let torus_distance = distance / 2_f64.powi(Raw::BITS as i32);
        assert!(
            torus_distance <= 5. * dist.get_standard_dev(),
            "{} != {} ",
            x,
            y
        );
    }
}

// pub fn assert_noise_distribution<First, Second, Element>(
//     first: &First,
//     second: &Second,
//     dist: impl DispersionParameter,
// ) where
//     First: AsRefTensor<Element = Element>,
//     Second: AsRefTensor<Element = Element>,
//     Element: UnsignedTorus,
// {
//     use crate::backends::core::private::math::tensor::Tensor;
//
//     let std_dev = dist.get_standard_dev();
//     let confidence = 0.95;
//     let n_slots = first.as_tensor().len();
//     let mut generator = RandomGenerator::new(None);
//
//     // allocate 2 slices: one for the error samples obtained, the second for fresh samples
//     // according to the std_dev computed
//     let mut sdk_samples = Tensor::allocate(0.0_f64, n_slots);
//
//     // recover the errors from each ciphertexts
//     sdk_samples.fill_with_two(first.as_tensor(), second.as_tensor(), |a, b| {
//         torus_modular_distance(*a, *b)
//     });
//
//     // fill the theoretical sample vector according to std_dev
//     let theoretical_samples = generator.random_gaussian_tensor(n_slots, 0., std_dev);
//
//     // compute the kolmogorov smirnov test
//     let result = kolmogorov_smirnov::test_f64(
//         sdk_samples.as_slice(),
//         theoretical_samples.as_slice(),
//         confidence,
//     );
//
//     if result.is_rejected {
//         // compute the mean of our errors
//         let mut mean: f64 = sdk_samples.iter().sum();
//         mean /= sdk_samples.len() as f64;
//
//         // compute the variance of the errors
//         let mut sdk_variance: f64 = sdk_samples.iter().map(|x| f64::powi(x - mean, 2)).sum();
//         sdk_variance /= (sdk_samples.len() - 1) as f64;
//
//         // compute the standard deviation
//         let sdk_std_log2 = f64::log2(f64::sqrt(sdk_variance)).round();
//         let th_std_log2 = f64::log2(std_dev).round();
//
//         // test if theoretical_std_dev > sdk_std_dev
//         assert!(
//             sdk_std_log2 <= th_std_log2,
//             "Statistical test failed :
//                     -> inputs are not from the same distribution with a probability {}
//                     -> sdk_std = {} ; th_std {}.",
//             result.reject_probability,
//             sdk_std_log2,
//             th_std_log2
//         );
//     }
// }
