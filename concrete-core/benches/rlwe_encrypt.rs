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
use concrete_core::math::random::{
    fill_with_random_uniform, fill_with_random_uniform_boolean, random_uniform_n_msb,
    RandomGenerable, UniformMsb,
};
use concrete_core::math::tensor::{
    AsMutSlice, AsMutTensor, AsRefSlice, AsRefTensor, IntoTensor, Tensor,
};
use concrete_core::numeric::{CastFrom, CastInto, Numeric};

pub fn bench<T: UnsignedTorus + CastFrom<u64>>(c: &mut Criterion) {
    let rlwe_dimensions = vec![1];
    let degrees = vec![1024];

    let params = iproduct!(rlwe_dimensions, degrees);

    let mut group = c.benchmark_group("rlwe_encrypt");
    for p in params {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("p={}-k={}-N={}", T::BITS, p.0, p.1,)),
            &p,
            |b, p| {
                // --------> all allocation
                let polynomial_size = PolynomialSize(p.1);
                let rlwe_dimension = GlweDimension(p.0);
                let std = LogStandardDev::from_log_standard_dev(-29.);

                // allocate secret keys
                let mut rlwe_sk = GlweSecretKey::generate(rlwe_dimension, polynomial_size);

                let mut ciphertext = GlweCiphertext::allocate(
                    T::ZERO,
                    polynomial_size,
                    rlwe_dimension.to_glwe_size(),
                );
                let plaintext = PlaintextList::allocate(T::ZERO, PlaintextCount(polynomial_size.0));

                b.iter(|| rlwe_sk.encrypt_glwe(&mut ciphertext, &plaintext, std));
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
