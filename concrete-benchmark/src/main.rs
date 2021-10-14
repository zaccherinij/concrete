//! An application to execute benchmarks on `concrete-core` operators.
//!
//! This application contains generic benchmarking functions, which makes it possible to benchmark
//! every operators of the `concrete-core` library, using the same function. Then, benchmarking a
//! new backend mainly consists in appropriately instantiating the benchmarks.

mod backends;
mod generics;
mod utils;

// The main entry point. Uses criterion as benchmark harness.
fn main() {
    // We instantiate the benchmarks for different backends depending on the feature flag activated.
    #[cfg(feature = "core_backend")]
    backends::core::bench();

    // We launch the benchmarks.
    criterion::Criterion::default()
        .configure_from_args()
        .final_summary();
}
