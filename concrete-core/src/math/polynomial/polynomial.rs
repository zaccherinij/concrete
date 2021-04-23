use std::fmt::Debug;
use std::iter::Iterator;

use crate::math::tensor::{AsMutSlice, AsMutTensor, AsRefTensor, Tensor};
use crate::numeric::{CastFrom, UnsignedInteger};
use crate::{ck_dim_eq, tensor_traits};

use super::*;

const KARATUSBA_STOP: usize = 32;

/// A dense polynomial.
///
/// This type represent a dense polynomial in $\mathbb{Z}_{2^q}\[X\] / <X^N + 1>$, composed of $N$
/// integer coefficients encoded on $q$ bits.
///
///  # Example:
///
/// ```
/// use concrete_core::math::polynomial::{Polynomial, PolynomialSize};
/// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
/// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
/// ```
#[derive(PartialEq, Debug, Clone)]
pub struct Polynomial<Cont> {
    pub(crate) tensor: Tensor<Cont>,
}

tensor_traits!(Polynomial);

impl<Scalar> Polynomial<Vec<Scalar>>
where
    Scalar: Copy,
{
    /// Allocates a new polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize};
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn allocate(value: Scalar, coef_count: PolynomialSize) -> Polynomial<Vec<Scalar>> {
        Polynomial::from_container(vec![value; coef_count.0])
    }
}

impl<Cont> Polynomial<Cont> {
    /// Creates a polynomial from a container of values.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize};
    /// let vec = vec![0 as u32; 100];
    /// let poly = Polynomial::from_container(vec.as_slice());
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn from_container(cont: Cont) -> Self {
        Polynomial {
            tensor: Tensor::from_container(cont),
        }
    }

    /// Returns the number of coefficients in the polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize};
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// assert_eq!(poly.polynomial_size(), PolynomialSize(100));
    /// ```
    pub fn polynomial_size(&self) -> PolynomialSize
    where
        Self: AsRefTensor,
    {
        PolynomialSize(self.as_tensor().len())
    }

    /// Builds an iterator over `Monomial<&Coef>` elements.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree, PolynomialSize};
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for monomial in poly.monomial_iter(){
    ///     assert!(monomial.degree().0 <= 99)
    /// }
    /// assert_eq!(poly.monomial_iter().count(), 100);
    /// ```
    pub fn monomial_iter(&self) -> impl Iterator<Item = Monomial<&[<Self as AsRefTensor>::Element]>>
    where
        Self: AsRefTensor,
    {
        self.as_tensor()
            .subtensor_iter(1)
            .enumerate()
            .map(|(i, coef)| Monomial::from_container(coef.into_container(), MonomialDegree(i)))
    }

    /// Builds an iterator over `&Coef` elements, in order of increasing degree.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree, PolynomialSize};
    /// let poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for coef in poly.coefficient_iter(){
    ///     assert_eq!(*coef, 0);
    /// }
    /// assert_eq!(poly.coefficient_iter().count(), 100);
    /// ```
    pub fn coefficient_iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = &<Self as AsRefTensor>::Element>
    where
        Self: AsRefTensor,
    {
        self.as_tensor().iter()
    }

    /// Returns the monomial of a given degree.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize, MonomialDegree};
    /// let poly = Polynomial::from_container(vec![16_u32,8,19,12,3]);
    /// let mono = poly.get_monomial(MonomialDegree(0));
    /// assert_eq!(*mono.get_coefficient(), 16_u32);
    /// let mono = poly.get_monomial(MonomialDegree(2));
    /// assert_eq!(*mono.get_coefficient(), 19_u32);
    /// ```
    pub fn get_monomial(
        &self,
        degree: MonomialDegree,
    ) -> Monomial<&[<Self as AsRefTensor>::Element]>
    where
        Self: AsRefTensor,
    {
        Monomial::from_container(
            self.as_tensor()
                .get_sub(degree.0..=degree.0)
                .into_container(),
            degree,
        )
    }

    /// Builds an iterator over `Monomial<&mut Coef>` elements.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{PolynomialSize, Polynomial};
    /// let mut poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for mut monomial in poly.monomial_iter_mut(){
    ///     monomial.set_coefficient(monomial.degree().0 as u32);
    /// }
    /// for (i, monomial) in poly.monomial_iter().enumerate(){
    ///     assert_eq!(*monomial.get_coefficient(), i as u32);
    /// }
    /// assert_eq!(poly.monomial_iter_mut().count(), 100);
    /// ```
    pub fn monomial_iter_mut(
        &mut self,
    ) -> impl Iterator<Item = Monomial<&mut [<Self as AsMutTensor>::Element]>>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor()
            .subtensor_iter_mut(1)
            .enumerate()
            .map(|(i, coef)| Monomial::from_container(coef.into_container(), MonomialDegree(i)))
    }

    /// Builds an iterator over `&mut Coef` elements, in order of increasing degree.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{PolynomialSize, Polynomial};
    /// let mut poly = Polynomial::allocate(0 as u32, PolynomialSize(100));
    /// for mut coef in poly.coefficient_iter_mut(){
    ///     *coef = 1;
    /// }
    /// for coef in poly.coefficient_iter(){
    ///     assert_eq!(*coef, 1);
    /// }
    /// assert_eq!(poly.coefficient_iter_mut().count(), 100);
    /// ```
    pub fn coefficient_iter_mut(
        &mut self,
    ) -> impl DoubleEndedIterator<Item = &mut <Self as AsMutTensor>::Element>
    where
        Self: AsMutTensor,
    {
        self.as_mut_tensor().iter_mut()
    }

    /// Returns the mutable monomial of a given degree.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize, MonomialDegree};
    /// let mut poly = Polynomial::from_container(vec![16_u32,8,19,12,3]);
    /// let mut mono = poly.get_mut_monomial(MonomialDegree(0));
    /// mono.set_coefficient(18);
    /// let mono = poly.get_monomial(MonomialDegree(0));
    /// assert_eq!(*mono.get_coefficient(), 18);
    /// ```
    pub fn get_mut_monomial(
        &mut self,
        degree: MonomialDegree,
    ) -> Monomial<&mut [<Self as AsMutTensor>::Element]>
    where
        Self: AsMutTensor,
    {
        Monomial::from_container(
            self.as_mut_tensor()
                .get_sub_mut(degree.0..=degree.0)
                .into_container(),
            degree,
        )
    }

    /// Fills the current polynomial, with the result of the product of two polynomials,
    /// reduced modulo $(X^N + 1)$.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize, MonomialDegree};
    /// let lhs = Polynomial::from_container(vec![4_u8, 5, 0]);
    /// let rhs = Polynomial::from_container(vec![7_u8, 9, 0]);
    /// let mut res = Polynomial::allocate(0 as u8, PolynomialSize(3));
    /// res.fill_with_wrapping_mul(&lhs, &rhs);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 28 as u8);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 71 as u8);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 45 as u8);
    /// ```
    pub fn fill_with_mul<Coef, PolynomialCont>(
        &mut self,
        polynomial_1: &Polynomial<PolynomialCont>,
        polynomial_2: &Polynomial<PolynomialCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolynomialCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        if self.polynomial_size().0 < KARATUSBA_STOP {
            self.fill_with_mul_schoolbook(polynomial_1, polynomial_2);
        } else {
            self.fill_with_mul_karatsuba(polynomial_1, polynomial_2);
        }
    }

    /// Fills the current polynomial, with the result of the slow product (schoolbook algorithm)
    /// of two polynomials, reduced modulo $(X^N + 1)$.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize, MonomialDegree};
    /// let lhs = Polynomial::from_container(vec![4_u8, 5, 0]);
    /// let rhs = Polynomial::from_container(vec![7_u8, 9, 0]);
    /// let mut res = Polynomial::allocate(0 as u8, PolynomialSize(3));
    /// res.fill_with_wrapping_schoolbook(&lhs, &rhs);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 28 as u8);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 71 as u8);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 45 as u8);
    /// ```
    pub fn fill_with_mul_schoolbook<Coef, PolynomialCont>(
        &mut self,
        polynomial_1: &Polynomial<PolynomialCont>,
        polynomial_2: &Polynomial<PolynomialCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolynomialCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(self.polynomial_size() => polynomial_1.polynomial_size(), polynomial_2.polynomial_size());
        self.coefficient_iter_mut().for_each(|a| *a = Coef::ZERO);
        let degree = polynomial_1.polynomial_size().0 - 1;
        for lhsi in polynomial_1.monomial_iter() {
            for rhsi in polynomial_2.monomial_iter() {
                let target_degree = lhsi.degree().0 + rhsi.degree().0;
                if target_degree <= degree {
                    let element = self.as_mut_tensor().get_element_mut(target_degree);
                    let new = lhsi.get_coefficient().wrapping_mul(*rhsi.get_coefficient());
                    *element = element.wrapping_add(new);
                } else {
                    let element = self
                        .as_mut_tensor()
                        .get_element_mut(target_degree % (degree + 1));
                    let new = lhsi.get_coefficient().wrapping_mul(*rhsi.get_coefficient());
                    *element = element.wrapping_sub(new);
                }
            }
        }
    }

    /// Fills the current polynomial, with the result of the product of two polynomials,
    /// reduced modulo $(X^N + 1)$.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialSize, MonomialDegree};
    /// let lhs = Polynomial::from_container(vec![1_u32; 128]);
    /// let rhs = Polynomial::from_container(vec![2_u32; 128]);
    /// let mut res_kara = Polynomial::allocate(0 as u32, PolynomialSize(128));
    /// let mut res_mul = Polynomial::allocate(0 as u32, PolynomialSize(128));
    /// res_kara.fill_with_karatsuba(&lhs, &rhs);
    /// res_mul.fill_with_wrapping_mul(&lhs, &rhs);
    /// assert_eq!(res_kara,res_mul);
    /// ```
    pub fn fill_with_mul_karatsuba<Coef, PolynomialCont>(
        &mut self,
        p: &Polynomial<PolynomialCont>,
        q: &Polynomial<PolynomialCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolynomialCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(self.polynomial_size() => p.polynomial_size(), q.polynomial_size());
        // todo check N is an actual 2power

        let poly_size = self.polynomial_size().0;

        // allocate slices for the rec
        let mut a0 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut a1 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut a2 = Tensor::allocate(Coef::ZERO, poly_size);
        let mut input_a2_p = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut input_a2_q = Tensor::allocate(Coef::ZERO, poly_size / 2);

        // prepare for splitting
        let bottom = 0..(poly_size / 2);
        let top = (poly_size / 2)..poly_size;

        // rec
        rec_mul_karatsuba(
            &mut a0.get_sub_mut(..),
            &p.as_tensor().get_sub(bottom.clone()),
            &q.as_tensor().get_sub(bottom.clone()),
        );
        rec_mul_karatsuba(
            &mut a1.get_sub_mut(..),
            &p.as_tensor().get_sub(top.clone()),
            &q.as_tensor().get_sub(top.clone()),
        );
        input_a2_p.fill_with_wrapping_add(
            &p.as_tensor().get_sub(bottom.clone()),
            &p.as_tensor().get_sub(top.clone()),
        );
        input_a2_q.fill_with_wrapping_add(
            &q.as_tensor().get_sub(bottom.clone()),
            &q.as_tensor().get_sub(top.clone()),
        );
        rec_mul_karatsuba(
            &mut a2.get_sub_mut(..),
            &input_a2_p.get_sub(..),
            &input_a2_q.get_sub(..),
        );

        // rebuild the result
        self.as_mut_tensor().fill_with_wrapping_sub(&a0, &a1);
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_sub(&a2.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_add(&a0.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(bottom.clone())
            .update_with_wrapping_add(&a1.get_sub(top.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top.clone())
            .update_with_wrapping_add(&a2.get_sub(bottom.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top.clone())
            .update_with_wrapping_sub(&a0.get_sub(bottom.clone()));
        self.as_mut_tensor()
            .get_sub_mut(top.clone())
            .update_with_wrapping_sub(&a1.get_sub(bottom.clone()));
    }

    /// Adds the sum of the element-wise product between a list of integer polynomial, and a
    /// list of binary polynomial, to the current polynomial.
    ///
    /// I.e., if the current polynomial is $C(X)$, for a collection of polynomials $(P_i(X)))_i$
    /// and a collection of binary polynomials $(B_i(X))_i$ we perform the operation:
    /// $$
    /// C(X) := C(X) + \sum_i P_i(X) \times B_i(X) mod (X^N + 1)
    /// $$
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{PolynomialList, PolynomialSize, Polynomial, MonomialDegree};
    /// let poly_list = PolynomialList::from_container(
    ///     vec![100 as u8,20,3,4,5,6],
    ///     PolynomialSize(3)
    /// );
    /// let bin_poly_list = PolynomialList::from_container(
    ///     vec![false, true, true, true, false, false],
    ///     PolynomialSize(3)
    /// );
    /// let mut output = Polynomial::allocate(250 as u8, PolynomialSize(3));
    /// output.update_with_wrapping_add_binary_multisum(&poly_list, &bin_poly_list);
    /// assert_eq!(*output.get_monomial(MonomialDegree(0)).get_coefficient(), 231);
    /// assert_eq!(*output.get_monomial(MonomialDegree(1)).get_coefficient(), 96);
    /// assert_eq!(*output.get_monomial(MonomialDegree(2)).get_coefficient(), 120);
    /// ```
    pub fn update_with_add_multisum<Coef, InCont>(
        &mut self,
        polynomial_list_1: &PolynomialList<InCont>,
        polynomial_list_2: &PolynomialList<InCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for (polynomial_1, polynomial_2) in polynomial_list_1
            .polynomial_iter()
            .zip(polynomial_list_2.polynomial_iter())
        {
            // allocation for the result of the multiplication
            let mut tmp = Polynomial::allocate(Coef::ZERO, self.polynomial_size());

            // multiplication
            tmp.fill_with_mul(&polynomial_1, &polynomial_2);

            // add to self
            self.update_with_add(&tmp);
        }
    }

    /// Subtracts the sum of the element-wise product between a list of integer polynomial, and a
    /// list of binary polynomial, to the current polynomial.
    ///
    /// I.e., if the current polynomial is $C(X)$, for a list of polynomials $(P_i(X)))_i$ and a
    /// list of  binary polynomials $(B_i(X))_i$ we perform the operation:
    /// $$
    /// C(X) := C(X) + \sum_i P_i(X) \times B_i(X) mod (X^N + 1)
    /// $$
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{PolynomialList, PolynomialSize, Polynomial, MonomialDegree};
    /// let poly_list = PolynomialList::from_container(
    ///     vec![100 as u8,20,3,4,5,6],
    ///     PolynomialSize(3)
    /// );
    /// let bin_poly_list = PolynomialList::from_container(
    ///     vec![false, true, true, true, false, false],
    ///     PolynomialSize(3)
    /// );
    /// let mut output = Polynomial::allocate(250 as u8, PolynomialSize(3));
    /// output.update_with_wrapping_sub_binary_multisum(&poly_list, &bin_poly_list);
    /// assert_eq!(*output.get_monomial(MonomialDegree(0)).get_coefficient(), 13);
    /// assert_eq!(*output.get_monomial(MonomialDegree(1)).get_coefficient(), 148);
    /// assert_eq!(*output.get_monomial(MonomialDegree(2)).get_coefficient(), 124);
    /// ```
    pub fn update_with_sub_multisum<Coef, InCont>(
        &mut self,
        polynomial_list_1: &PolynomialList<InCont>,
        polynomial_list_2: &PolynomialList<InCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for (polynomial_1, polynomial_2) in polynomial_list_1
            .polynomial_iter()
            .zip(polynomial_list_2.polynomial_iter())
        {
            // allocation for the result of the multiplication
            let mut tmp = Polynomial::allocate(Coef::ZERO, self.polynomial_size());

            // multiplication
            tmp.fill_with_mul(&polynomial_1, &polynomial_2);

            // add to self
            self.update_with_sub(&tmp);
        }
    }
    /// Adds the result of the product between a integer polynomial and a binary one, reduced
    /// modulo $(X^N+1)$, to the current polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let poly = Polynomial::from_container(vec![1_u8,2,3]);
    /// let bin_poly = Polynomial::from_container(vec![false, true, true]);
    /// let mut res = Polynomial::from_container(vec![1_u8, 0, 253]);
    /// res.update_with_wrapping_add_binary_mul(&poly, &bin_poly);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 252);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 254);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 0);
    /// ```
    pub fn update_with_add_mul<Coef, PolyCont>(
        &mut self,
        polynomial_1: &Polynomial<PolyCont>,
        polynomial_2: &Polynomial<PolyCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolyCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            polynomial_1.polynomial_size(),
            polynomial_2.polynomial_size()
        );

        // allocation for the result of the multiplication
        let mut tmp = Polynomial::allocate(Coef::ZERO, self.polynomial_size());

        // multiplication
        tmp.fill_with_mul(polynomial_1, polynomial_2);

        // add to self
        self.update_with_add(&tmp);
    }

    /// Subtracts the result of the product between an integer polynomial and a binary one, reduced
    /// modulo $(X^N+1)$, to the current polynomial.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let poly = Polynomial::from_container(vec![1_u8,2,3]);
    /// let bin_poly = Polynomial::from_container(vec![false, true, true]);
    /// let mut res = Polynomial::from_container(vec![255_u8, 255, 1]);
    /// res.update_with_wrapping_sub_binary_mul(&poly, &bin_poly);
    /// assert_eq!(*res.get_monomial(MonomialDegree(0)).get_coefficient(), 4);
    /// assert_eq!(*res.get_monomial(MonomialDegree(1)).get_coefficient(), 1);
    /// assert_eq!(*res.get_monomial(MonomialDegree(2)).get_coefficient(), 254);
    /// ```
    pub fn update_with_sub_mul<Coef, PolyCont>(
        &mut self,
        polynomial_1: &Polynomial<PolyCont>,
        polynomial_2: &Polynomial<PolyCont>,
    ) where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<PolyCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            polynomial_1.polynomial_size(),
            polynomial_2.polynomial_size()
        );

        // allocation for the result of the multiplication
        let mut tmp = Polynomial::allocate(Coef::ZERO, self.polynomial_size());

        // multiplication
        tmp.fill_with_mul(polynomial_1, polynomial_2);

        // add to self
        self.update_with_sub(&tmp);
    }

    /// Adds a integer polynomial to another one.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let mut first = Polynomial::from_container(vec![1u8, 2, 3]);
    /// let second = Polynomial::from_container(vec![255u8, 255, 255]);
    /// first.update_with_wrapping_add(&second);
    /// assert_eq!(*first.get_monomial(MonomialDegree(0)).get_coefficient(), 0);
    /// assert_eq!(*first.get_monomial(MonomialDegree(1)).get_coefficient(), 1);
    /// assert_eq!(*first.get_monomial(MonomialDegree(2)).get_coefficient(), 2);
    /// ```
    pub fn update_with_add<Coef, OtherCont>(&mut self, other: &Polynomial<OtherCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<OtherCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            other.polynomial_size()
        );
        self.as_mut_tensor()
            .update_with_wrapping_add(other.as_tensor());
    }

    /// Subtracts an integer polynomial to another one.
    ///
    /// # Example
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let mut first = Polynomial::from_container(vec![1u8, 2, 3]);
    /// let second = Polynomial::from_container(vec![4u8, 5, 6]);
    /// first.update_with_wrapping_sub(&second);
    /// assert_eq!(*first.get_monomial(MonomialDegree(0)).get_coefficient(), 253);
    /// assert_eq!(*first.get_monomial(MonomialDegree(1)).get_coefficient(), 253);
    /// assert_eq!(*first.get_monomial(MonomialDegree(2)).get_coefficient(), 253);
    /// ```
    pub fn update_with_sub<Coef, OtherCont>(&mut self, other: &Polynomial<OtherCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        Polynomial<OtherCont>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        ck_dim_eq!(
            self.polynomial_size() =>
            other.polynomial_size()
        );
        self.as_mut_tensor()
            .update_with_wrapping_sub(other.as_tensor());
    }

    /// Multiplies (mod $(X^N+1)$), the current polynomial with a monomial of a given degree, and
    /// a coefficient of one.
    ///
    /// # Examples
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let mut poly = Polynomial::from_container(vec![1u8,2,3]);
    /// poly.update_with_wrapping_monic_monomial_mul(MonomialDegree(2));
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 254);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 253);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 1);
    /// ```
    pub fn update_with_monic_monomial_mul<Coef>(&mut self, monomial_degree: MonomialDegree)
    where
        Self: AsMutTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        let full_cycles_count = monomial_degree.0 / self.as_tensor().len();
        if full_cycles_count % 2 != 0 {
            self.as_mut_tensor()
                .as_mut_slice()
                .iter_mut()
                .for_each(|a| *a = a.wrapping_neg());
        }
        let remaining_degree = monomial_degree.0 % self.as_tensor().len();
        self.as_mut_tensor()
            .as_mut_slice()
            .rotate_right(remaining_degree);
        self.as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }

    /// Divides (mod $(X^N+1)$), the current polynomial with a monomial of a given degree, and a
    /// coefficient of one.
    ///
    /// # Examples
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, MonomialDegree};
    /// let mut poly = Polynomial::from_container(vec![1u8,2,3]);
    /// poly.update_with_wrapping_unit_monomial_div(MonomialDegree(2));
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 3);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 255);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 254);
    /// ```
    pub fn update_with_monic_monomial_div<Coef>(&mut self, monomial_degree: MonomialDegree)
    where
        Self: AsMutTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        let full_cycles_count = monomial_degree.0 / self.as_tensor().len();
        if full_cycles_count % 2 != 0 {
            self.as_mut_tensor()
                .as_mut_slice()
                .iter_mut()
                .for_each(|a| *a = a.wrapping_neg());
        }
        let remaining_degree = monomial_degree.0 % self.as_tensor().len();
        self.as_mut_tensor()
            .as_mut_slice()
            .rotate_left(remaining_degree);
        self.as_mut_tensor()
            .as_mut_slice()
            .iter_mut()
            .rev()
            .take(remaining_degree)
            .for_each(|a| *a = a.wrapping_neg());
    }

    /// Adds multiple integer polynomials to the current one.
    ///
    /// # Examples
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialList, PolynomialSize};
    /// use concrete_core::math::polynomial::MonomialDegree;
    /// let mut poly = Polynomial::from_container(vec![1u8,2,3]);
    /// let poly_list = PolynomialList::from_container(vec![4u8,5,6,7,8,9], PolynomialSize(3));
    /// poly.update_with_wrapping_add_several(&poly_list);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 12);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 15);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 18);
    /// ```
    pub fn update_with_add_several<Coef, InCont>(&mut self, coef_list: &PolynomialList<InCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for poly in coef_list.polynomial_iter() {
            self.update_with_add(&poly);
        }
    }

    /// Subtracts multiple integer polynomials to the current one.
    ///
    /// # Examples
    ///
    /// ```
    /// use concrete_core::math::polynomial::{Polynomial, PolynomialList, PolynomialSize};
    /// use concrete_core::math::polynomial::MonomialDegree;
    /// let mut poly = Polynomial::from_container(vec![1u32,2,3]);
    /// let poly_list = PolynomialList::from_container(vec![4u32,5,6,7,8,9], PolynomialSize(3));
    /// poly.update_with_wrapping_sub_several(&poly_list);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(0)).get_coefficient(), 4294967286);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(1)).get_coefficient(), 4294967285);
    /// assert_eq!(*poly.get_monomial(MonomialDegree(2)).get_coefficient(), 4294967284);
    /// ```
    pub fn update_with_sub_several<Coef, InCont>(&mut self, coef_list: &PolynomialList<InCont>)
    where
        Self: AsMutTensor<Element = Coef>,
        PolynomialList<InCont>: AsRefTensor<Element = Coef>,
        for<'a> Polynomial<&'a [Coef]>: AsRefTensor<Element = Coef>,
        Coef: UnsignedInteger,
    {
        for poly in coef_list.polynomial_iter() {
            self.update_with_sub(&poly);
        }
    }
}

/// function used to compute the induction for the karatsuba algorithm
fn rec_mul_karatsuba<Coef>(res: &mut Tensor<&mut [Coef]>, p: &Tensor<&[Coef]>, q: &Tensor<&[Coef]>)
where
    Coef: UnsignedInteger,
{
    if p.len() == KARATUSBA_STOP {
        // schoolbook algorithm
        for i in 0..p.len() {
            for j in 0..q.len() {
                *res.get_element_mut(i + j) = res
                    .get_element(i + j)
                    .wrapping_add(p.get_element(i).wrapping_mul(*q.get_element(j)))
            }
        }
    } else {
        let poly_size = res.len();

        // allocate slices for the rec
        let mut a0 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut a1 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut a2 = Tensor::allocate(Coef::ZERO, poly_size / 2);
        let mut input_a2_p = Tensor::allocate(Coef::ZERO, poly_size / 4);
        let mut input_a2_q = Tensor::allocate(Coef::ZERO, poly_size / 4);

        // prepare for splitting
        let bottom = 0..(poly_size / 4);
        let top = (poly_size / 4)..(poly_size / 2);

        // rec
        rec_mul_karatsuba(
            &mut a0.get_sub_mut(..),
            &p.get_sub(bottom.clone()),
            &q.get_sub(bottom.clone()),
        );
        rec_mul_karatsuba(
            &mut a1.get_sub_mut(..),
            &p.get_sub(top.clone()),
            &q.get_sub(top.clone()),
        );
        input_a2_p
            .as_mut_tensor()
            .fill_with_wrapping_add(&p.get_sub(bottom.clone()), &p.get_sub(top.clone()));
        input_a2_q
            .as_mut_tensor()
            .fill_with_wrapping_add(&q.get_sub(bottom.clone()), &q.get_sub(top.clone()));
        rec_mul_karatsuba(
            &mut a2.get_sub_mut(..),
            &input_a2_p.get_sub(..),
            &input_a2_q.get_sub(..),
        );

        // rebuild the result
        res.get_sub_mut((poly_size / 4)..(3 * poly_size / 4))
            .as_mut_tensor()
            .fill_with_wrapping_sub(&a2, &a0);
        res.get_sub_mut((poly_size / 4)..(3 * poly_size / 4))
            .update_with_wrapping_sub(&a1);
        res.get_sub_mut(0..(poly_size / 2))
            .update_with_wrapping_add(&a0);
        res.get_sub_mut((poly_size / 2)..poly_size)
            .update_with_wrapping_add(&a1);
    }
}
