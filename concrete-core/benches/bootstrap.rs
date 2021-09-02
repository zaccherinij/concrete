use criterion::{BenchmarkId, Criterion};
use itertools::iproduct;

use concrete_commons::dispersion::LogStandardDev;
use concrete_commons::numeric::{CastFrom, Numeric};
use concrete_commons::parameters::{
    DecompositionBaseLog, DecompositionLevelCount, GlweDimension, LweDimension, LweSize,
    PolynomialSize,
};

use concrete_core::crypto::bootstrap::{Bootstrap, FourierBootstrapKey};
use concrete_core::crypto::encoding::Plaintext;
use concrete_core::crypto::glwe::GlweCiphertext;
use concrete_core::crypto::lwe::LweCiphertext;
use concrete_core::crypto::secret::generators::{EncryptionRandomGenerator, SecretRandomGenerator};
use concrete_core::crypto::secret::LweSecretKey;
use concrete_core::math::fft::Complex64;
use concrete_core::math::tensor::AsMutTensor;
use concrete_core::math::torus::UnsignedTorus;

pub fn bench<T: UnsignedTorus + CastFrom<u64>>(c: &mut Criterion) {
    let values = vec![
        (1, 1024, 472, 2, 8),
        (1, 1024, 514, 2, 8),
        (1, 1024, 564, 2, 8),
        (1, 1024, 599, 3, 6),
        (1, 1024, 686, 3, 6),
        (1, 2048, 737, 1, 21),
        (1, 4096, 848, 1, 21),
        (1, 4096, 900, 10, 4),
        (1, 2048, 510, 4, 8),
        (1, 2048, 538, 5, 7),
        (1, 2048, 629, 5, 7),
        (1, 2048, 650, 7, 5),
        (1, 2048, 674, 10, 4),
        (1, 2048, 741, 19, 2),
        (1, 4096, 900, 10, 4),
    ];
    let mut group = c.benchmark_group("bootstrap");
    let mut secret_generator = SecretRandomGenerator::new(None);
    let mut encryption_generator = EncryptionRandomGenerator::new(None);
    for p in values {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!(
                "(p={}, k={}, N={}, n={}, l={}, B={})",
                T::BITS,
                p.0,
                p.1,
                p.2,
                p.3,
                p.4
            )),
            &p,
            |b, p| {
                // --------> all allocation
                let polynomial_size = PolynomialSize(p.1);
                let rlwe_dimension = GlweDimension(p.0);
                let lwe_dimension = LweDimension(p.2);
                let level = DecompositionLevelCount(p.3);
                let base_log = DecompositionBaseLog(p.4);
                let std = LogStandardDev::from_log_standard_dev(-29.);

                let lwe_sk = LweSecretKey::generate_binary(lwe_dimension, &mut secret_generator);

                let fourier_bsk = FourierBootstrapKey::allocate(
                    Complex64::new(0., 0.),
                    rlwe_dimension.to_glwe_size(),
                    polynomial_size,
                    level,
                    base_log,
                    lwe_dimension,
                );

                // msg to bootstrap
                let m0 = T::cast_from(
                    (2. / polynomial_size.0 as f64) * f64::powi(2., <T as Numeric>::BITS as i32),
                );
                let m0 = Plaintext(m0);
                let mut lwe_in = LweCiphertext::allocate(T::ZERO, lwe_dimension.to_lwe_size());
                let mut lwe_out = LweCiphertext::allocate(
                    T::ZERO,
                    LweSize(rlwe_dimension.0 * polynomial_size.0 + 1),
                );
                // accumulator is a trivial encryption of [0, 1/2N, 2/2N, ...]
                let mut accumulator = GlweCiphertext::allocate(
                    T::ZERO,
                    polynomial_size,
                    rlwe_dimension.to_glwe_size(),
                );

                lwe_sk.encrypt_lwe(&mut lwe_in, &m0, std, &mut encryption_generator);

                // fill accumulator
                for (i, elt) in accumulator
                    .get_mut_body()
                    .as_mut_tensor()
                    .iter_mut()
                    .enumerate()
                {
                    let val: u64 = (i as f64 / (2. * polynomial_size.0 as f64)
                        * f64::powi(2., <T as Numeric>::BITS as i32))
                    .round() as u64;

                    *elt = T::cast_from(val);
                }
                b.iter(|| {
                    fourier_bsk.bootstrap(&mut lwe_out, &lwe_in, &accumulator);
                });
            },
        );
    }
    group.finish();
}

pub fn bench_32(c: &mut Criterion) {
    bench::<u32>(c);
}

pub fn bench_64(c: &mut Criterion) {
    bench::<u64>(c);
}
