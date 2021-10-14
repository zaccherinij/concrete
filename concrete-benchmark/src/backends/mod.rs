//! A module containing backends benchmarks.
//!
//! Each submodule here is expected to be activated by a given feature flag (matching the
//! `*_backend` naming), and to contain a benchmark function containing the benchmarking of every
//! entry points exposed by the backend.

#[cfg(feature = "core_backend")]
pub mod core;
