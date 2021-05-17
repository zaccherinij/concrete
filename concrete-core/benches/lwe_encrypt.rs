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
    let lwe_dimensions = vec![1024];

    let mut group = c.benchmark_group("lwe_encrypt");
    for p in lwe_dimensions.iter() {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("p={}-n={}", T::BITS, p)),
            &p,
            |b, p| {
                // --------> all allocation
                let lwe_dimension = LweDimension(**p as usize);
                let std = LogStandardDev::from_log_standard_dev(-29.);
                let mut gen = RandomGenerator::new(None);

                // allocate secret keys
                let mut sk = LweSecretKey::generate(lwe_dimension, &mut gen);

                let mut ciphertext = LweCiphertext::allocate(T::ZERO, lwe_dimension.to_lwe_size());
                let plaintext = Plaintext(T::ZERO);

                let mut rng = EncryptionRng::new(None);
                b.iter(|| sk.encrypt_lwe(&mut ciphertext, &plaintext, std, &mut rng));
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
