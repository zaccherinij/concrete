use crate::specification::entities::markers::{GlweCiphertextKind, KeyDistributionMarker};
use crate::specification::entities::AbstractEntity;
use concrete_commons::parameters::{GlweDimension, PolynomialSize};

/// A trait implemented by types embodying a GLWE ciphertext.
///
/// A GLWE ciphertext is associated with a
/// [`KeyDistribution`](`GlweCiphertextEntity::KeyDistribution`) type, which conveys the distribution of the
/// secret key it was encrypted with.
///
/// # Formal Definition
///
/// Despite the fact that the GLWE scheme theoretically encompass the LWE scheme, in `concrete`, we forbid the
/// use of GLWE ciphertext entities to represent encryption of polynomials of size zero.
pub trait GlweCiphertextEntity: AbstractEntity<Kind = GlweCiphertextKind> {
    /// The distribution of the key the ciphertext was encrypted with.
    type KeyDistribution: KeyDistributionMarker;

    /// Returns the GLWE dimension of the ciphertext.
    fn glwe_dimension(&self) -> GlweDimension;

    /// Returns the polynomial size of the ciphertext.
    fn polynomial_size(&self) -> PolynomialSize;
}
