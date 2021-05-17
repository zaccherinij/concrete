use criterion::{criterion_group, criterion_main, Benchmark, BenchmarkId, Criterion};
use itertools::iproduct;
use rand::Rng;

use concrete_core::crypto::bootstrap::BootstrapKey;
use concrete_core::crypto::cross::{bootstrap, cmux, constant_sample_extract, external_product};
use concrete_core::crypto::encoding::{Plaintext, PlaintextList};
use concrete_core::crypto::glwe::{GlweCiphertext, GlweList};
use concrete_core::crypto::lwe::{LweCiphertext, LweKeyswitchKey};
use concrete_core::crypto::secret::{GlweSecretKey, LweSecretKey};
use concrete_core::crypto::{
    CiphertextCount, GlweDimension, LweDimension, LweSize, PlaintextCount, UnsignedTorus,
};
use concrete_core::math::decomposition::{DecompositionBaseLog, DecompositionLevelCount};
use concrete_core::math::dispersion::{DispersionParameter, LogStandardDev, Variance};
use concrete_core::math::fft::{Complex64, Fft, FourierPolynomial};
use concrete_core::math::polynomial::PolynomialSize;
use concrete_core::math::random::{EncryptionRng, RandomGenerable, RandomGenerator, UniformMsb};
use concrete_core::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use concrete_core::numeric::{CastFrom, CastInto, Numeric};

pub fn bench<T: UnsignedTorus + CastFrom<u64>>(c: &mut Criterion) {
    let lwe_dimensions = vec![600];
    let l_gadgets = vec![2];
    let rlwe_dimensions = vec![1];
    let degrees = vec![1024];
    let base_log = 17;
    let std = f64::powi(2., -23);

    let params = iproduct!(lwe_dimensions, l_gadgets, rlwe_dimensions, degrees);

    let mut group = c.benchmark_group("bsk_generation");
    for p in params {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!(
                "p={}-n={}-l={}-k={}-N={}",
                T::BITS,
                p.0,
                p.1,
                p.2,
                p.3
            )),
            &p,
            |b, p| {
                // --------> all allocation
                let polynomial_size = PolynomialSize(p.3);
                let rlwe_dimension = GlweDimension(p.2);
                let lwe_dimension = LweDimension(p.0);
                let level = DecompositionLevelCount(p.1);
                let base_log = DecompositionBaseLog(7);
                let std = LogStandardDev::from_log_standard_dev(-29.);

                // allocate secret keys
                let mut generator = RandomGenerator::new(None);
                let mut rlwe_sk =
                    GlweSecretKey::generate(rlwe_dimension, polynomial_size, &mut generator);
                let mut lwe_sk = LweSecretKey::generate(lwe_dimension, &mut generator);
                let mut bsk = BootstrapKey::allocate(
                    T::ZERO,
                    rlwe_dimension.to_glwe_size(),
                    polynomial_size,
                    level,
                    base_log,
                    lwe_dimension,
                );
                let mut fourier_bsk = BootstrapKey::allocate_complex(
                    Complex64::new(0., 0.),
                    rlwe_dimension.to_glwe_size(),
                    polynomial_size,
                    level,
                    base_log,
                    lwe_dimension,
                );

                let mut rng = EncryptionRng::new(None);
                b.iter(|| {
                    bsk.fill_with_new_key(&lwe_sk, &rlwe_sk, std, &mut rng);
                    fourier_bsk.fill_with_forward_fourier(&bsk);
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

pub fn bench_multi<T: UnsignedTorus + CastFrom<u64> + Send + Sync>(c: &mut Criterion) {
    let lwe_dimensions = vec![600];
    let l_gadgets = vec![2];
    let rlwe_dimensions = vec![1];
    let degrees = vec![1024];
    let base_log = 17;
    let std = f64::powi(2., -23);

    let params = iproduct!(lwe_dimensions, l_gadgets, rlwe_dimensions, degrees);

    let mut group = c.benchmark_group("bsk_generation_multi");
    for p in params {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!(
                "p={}-n={}-l={}-k={}-N={}",
                T::BITS,
                p.0,
                p.1,
                p.2,
                p.3
            )),
            &p,
            |b, p| {
                // --------> all allocation
                let polynomial_size = PolynomialSize(p.3);
                let rlwe_dimension = GlweDimension(p.2);
                let lwe_dimension = LweDimension(p.0);
                let level = DecompositionLevelCount(p.1);
                let base_log = DecompositionBaseLog(7);
                let std = LogStandardDev::from_log_standard_dev(-29.);

                // allocate secret keys
                let mut generator = RandomGenerator::new(None);
                let mut rlwe_sk =
                    GlweSecretKey::generate(rlwe_dimension, polynomial_size, &mut generator);
                let mut lwe_sk = LweSecretKey::generate(lwe_dimension, &mut generator);
                let mut bsk = BootstrapKey::allocate(
                    T::ZERO,
                    rlwe_dimension.to_glwe_size(),
                    polynomial_size,
                    level,
                    base_log,
                    lwe_dimension,
                );
                let mut fourier_bsk = BootstrapKey::allocate_complex(
                    Complex64::new(0., 0.),
                    rlwe_dimension.to_glwe_size(),
                    polynomial_size,
                    level,
                    base_log,
                    lwe_dimension,
                );

                let mut rng = EncryptionRng::new(None);
                b.iter(|| {
                    bsk.fill_with_new_key_multi(&lwe_sk, &rlwe_sk, std, &mut rng);
                    fourier_bsk.fill_with_forward_fourier(&bsk);
                });
            },
        );
    }
    group.finish();
}

pub fn bench_multi_32(c: &mut Criterion) {
    bench_multi::<u32>(c);
}

pub fn bench_multi_64(c: &mut Criterion) {
    bench_multi::<u64>(c);
}
