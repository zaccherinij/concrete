//! Fourier transform for polynomials.
//!
//! This module provides the tools to perform a fast product of two polynomials, reduced modulo
//! $X^N+1$, using the fast fourier transform.

#[cfg(test)]
mod tests;

mod twiddles;
use twiddles::*;

mod plans;
use plans::*;

mod polynomial;
pub use polynomial::*;

mod transform;
pub use transform::*;

/// A complex number encoded over two `f32`.
pub type Complex32 = fftw::types::c32;
/// A complex number encoded over two `f64`.
pub type Complex64 = fftw::types::c64;
/// A complex number encoded over two `f128`.
pub type Complex128 = fftw::types::c128;
