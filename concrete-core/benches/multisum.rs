use criterion::{criterion_group, criterion_main, Benchmark, BenchmarkId, Criterion};
use itertools::iproduct;
use rand::Rng;

use concrete_core::crypto::bootstrap::BootstrapKey;
use concrete_core::crypto::cross::{bootstrap, cmux, constant_sample_extract, external_product};
use concrete_core::crypto::encoding::{CleartextList, Plaintext, PlaintextList};
use concrete_core::crypto::glwe::{GlweCiphertext, GlweList};
use concrete_core::crypto::lwe::{LweCiphertext, LweKeyswitchKey, LweList};
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

pub fn bench<T: UnsignedTorus + RandomGenerable<UniformMsb>>(c: &mut Criterion) {
    // fix a set of parameters
    let multisum_size = vec![2048];
    let dimension = vec![700];
    let params = iproduct!(multisum_size, dimension);
    let mut group = c.benchmark_group("multisum");
    for p in params {
        // group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("p={}-SumSize={}-n={}", T::BITS, p.0, p.1)),
            &p,
            |b, p| {
                let sum_size = p.0;
                let dimension = LweDimension(p.1);
                let mut ciphertext_values = LweList::from_container(
                    vec![T::ZERO; sum_size * dimension.to_lwe_size().0],
                    dimension.to_lwe_size(),
                );

                let mut output =
                    LweCiphertext::from_container(vec![T::ZERO; dimension.to_lwe_size().0]);
                let weights = CleartextList::from_container(vec![T::ONE; sum_size]);
                let bias = Plaintext(T::ONE);

                b.iter(|| {
                    output.fill_with_multisum_with_bias(&ciphertext_values, &weights, &bias);
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
