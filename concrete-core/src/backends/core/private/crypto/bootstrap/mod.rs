//! Bootstrapping keys.
//!
//! The bootstrapping operation allows to reduce the level of noise in an LWE ciphertext, while
//! evaluating an univariate function.

use concrete_commons::parameters::{GlweSize, PolynomialSize};
use concrete_fftw::array::AlignedVec;
pub use fourier::FourierBootstrapKey;
pub use standard::StandardBootstrapKey;

use crate::backends::core::private::crypto::glwe::GlweCiphertext;
use crate::backends::core::private::math::fft::{Complex64, Fft, FourierPolynomial};
use crate::backends::core::private::math::tensor::Tensor;
use crate::backends::core::private::math::torus::UnsignedTorus;
use crate::prelude::LweBootstrapKeyEntity;

mod fourier;
mod standard;
// mod surrogate;

#[derive(Debug, Clone)]
pub struct FftBuffers {
    // The fft plan is stored here. This way, we don't pay the price of allocating it every
    // time we need to bootstrap with the same key.
    fft: Fft,
    // The buffers used to perform the fft are also stored in the bootstrap key. Again, the same
    // logic apply, and we don't have to allocate them multiple times.
    first_buffer: FourierPolynomial<AlignedVec<Complex64>>,
    second_buffer: FourierPolynomial<AlignedVec<Complex64>>,
    output_buffer: Tensor<AlignedVec<Complex64>>,
}

#[derive(Debug, Clone)]
pub struct FourierBskBuffers<Scalar> {
    // Those buffers are also used to store the lut and the rounded input during the bootstrap.
    lut_buffer: GlweCiphertext<Vec<Scalar>>,
    rounded_buffer: GlweCiphertext<Vec<Scalar>>,
    fft_buffers: FftBuffers,
}

impl<Scalar> FourierBskBuffers<Scalar>
where
    Scalar: UnsignedTorus,
{
    pub fn for_key<Key: LweBootstrapKeyEntity>(key: &Key) -> Self {
        let poly_size = key.polynomial_size();
        let glwe_size = key.glwe_dimension().to_glwe_size();
        Self::new(poly_size, glwe_size)
    }

    pub fn new(poly_size: PolynomialSize, glwe_size: GlweSize) -> Self {
        let fft = Fft::new(poly_size);
        let first_buffer = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
        let second_buffer = FourierPolynomial::allocate(Complex64::new(0., 0.), poly_size);
        let output_buffer = Tensor::from_container(AlignedVec::new(poly_size.0 * glwe_size.0));
        let lut_buffer = GlweCiphertext::allocate(Scalar::ZERO, poly_size, glwe_size);
        let rounded_buffer = GlweCiphertext::allocate(Scalar::ZERO, poly_size, glwe_size);

        Self {
            lut_buffer,
            rounded_buffer,
            fft_buffers: FftBuffers {
                fft,
                first_buffer,
                second_buffer,
                output_buffer,
            },
        }
    }
}

#[cfg(all(test, feature = "multithread"))]
mod test {
    use crate::backends::core::private::crypto::bootstrap::StandardBootstrapKey;
    use crate::backends::core::private::crypto::secret::generators::{
        EncryptionRandomGenerator, SecretRandomGenerator,
    };
    use crate::backends::core::private::crypto::secret::{GlweSecretKey, LweSecretKey};
    use crate::backends::core::private::math::torus::UnsignedTorus;
    use concrete_commons::dispersion::StandardDev;
    use concrete_commons::parameters::{
        DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, PolynomialSize,
    };

    fn test_bsk_gen_equivalence<T: UnsignedTorus + Send + Sync>() {
        for _ in 0..10 {
            let lwe_dim = LweDimension(
                crate::backends::core::private::test_tools::random_usize_between(5..10),
            );
            let glwe_dim = GlweDimension(
                crate::backends::core::private::test_tools::random_usize_between(5..10),
            );
            let poly_size = PolynomialSize(
                crate::backends::core::private::test_tools::random_usize_between(5..10),
            );
            let level = DecompositionLevelCount(
                crate::backends::core::private::test_tools::random_usize_between(2..5),
            );
            let base_log = DecompositionBaseLog(
                crate::backends::core::private::test_tools::random_usize_between(2..5),
            );
            let mask_seed = crate::backends::core::private::test_tools::any_usize() as u128;
            let noise_seed = crate::backends::core::private::test_tools::any_usize() as u128;

            let mut secret_generator = SecretRandomGenerator::new(None);
            let lwe_sk = LweSecretKey::generate_binary(lwe_dim, &mut secret_generator);
            let glwe_sk =
                GlweSecretKey::generate_binary(glwe_dim, poly_size, &mut secret_generator);

            let mut mono_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator = EncryptionRandomGenerator::new(Some(mask_seed));
            encryption_generator.seed_noise_generator(noise_seed);
            mono_bsk.fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            let mut multi_bsk = StandardBootstrapKey::allocate(
                T::ZERO,
                glwe_dim.to_glwe_size(),
                poly_size,
                level,
                base_log,
                lwe_dim,
            );
            let mut encryption_generator = EncryptionRandomGenerator::new(Some(mask_seed));
            encryption_generator.seed_noise_generator(noise_seed);
            multi_bsk.par_fill_with_new_key(
                &lwe_sk,
                &glwe_sk,
                StandardDev::from_standard_dev(10.),
                &mut encryption_generator,
            );

            assert_eq!(mono_bsk, multi_bsk);
        }
    }

    #[test]
    fn test_bsk_gen_equivalence_u32() {
        test_bsk_gen_equivalence::<u32>()
    }

    #[test]
    fn test_bsk_gen_equivalence_u64() {
        test_bsk_gen_equivalence::<u64>()
    }
}
