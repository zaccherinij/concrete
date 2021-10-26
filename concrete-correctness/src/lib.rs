//! A library containing generic tests for `concrete-core` operators.
//!
//! This application contains generic benchmarking functions, which makes it possible to benchmark
//! every operators of the `concrete-core` library, using the same function. Then, benchmarking a
//! new backend mainly consists in appropriately instantiating the benchmarks.

mod backends;
mod generics;
mod utils;
