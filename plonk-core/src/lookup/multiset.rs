// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::{Field, FftField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain};
use ark_serialize::*;
use core::ops::{Add, Mul, Deref, DerefMut};
use indexmap::IndexMap;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{error::Error, util::poly_from_evals};

/// MultiSet is struct containing vectors of scalars, which
/// individually represents either a wire value or an index
/// of a PlookUp table
#[derive(
    CanonicalDeserialize,
    CanonicalSerialize,
    Clone,
    Debug,
    Default,
    Eq,
    PartialEq,
)]
pub struct MultiSet<F: Field>(pub Vec<F>);

#[allow(dead_code)]
impl<F: Field> MultiSet<F> {
    /// Creates an empty vector with a multiset wrapper around it
    pub fn new() -> Self {
        Default::default()
    }

    /// Creates a [`MultiSet`] witch capacity for `len` elements
    pub fn with_capacity(len: usize) -> Self {
        MultiSet(Vec::with_capacity(len))
    }

    /// Extends the length of the multiset to n elements The `n` will be the
    /// size of the arithmetic circuit. This will extend the vectors to the
    /// size
    pub(super) fn pad_with_zero(&mut self, n: usize) {
        assert!(n.is_power_of_two());
        if n > self.len() {
            self.0.resize(n, F::zero())
        }
    }

    /// Pushes chosen value onto the end of the Multiset
    pub fn push(&mut self, value: F) {
        self.0.push(value)
    }

    // /// Extendes values onto the end of the Multiset
    // pub fn extend<T>(&mut self, iter: T)
    // where
    //     T: IntoIterator<Item = F>,
    // {
    //     self.0.extend(iter)
    // }

    /// Fetches last element in MultiSet.
    /// Returns None if there are no elements in the MultiSet.
    pub fn last(&self) -> Option<&F> {
        self.0.last()
    }

    /// Returns the cardinality of the multiset
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether or not the multiset is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the position of the element in the Multiset.
    /// Returns None if the element is not found.
    pub fn position(&self, element: &F) -> Option<usize> {
        self.0.iter().position(move |x| x == element)
    }

    /// Combines two multisets and splits them into alternating halves
    /// of the same length, subject to the ordering in the multiset
    /// calling the method (t).
    /// All elements of the incoming multiset f must exist in t.
    ///
    /// Field elements in both multisets are first grouped into buckets of the
    /// same value. Then the buckets are concatenated in the same order as
    /// the elements of t and and split into even and odd-indexed halves.
    /// This is a more efficient way to arrive at a "sorted concatenation" of
    /// two multisets that avoids performing a sort.
    ///
    /// From the Plonkup paper, if we have t: {2,4,1,3} and f: {2,3,3,2},
    /// the combined multiset will look as follows, s: {2,2,2,4,1,3,3,3}.
    /// Then the two even-and-odd halves will be: h1: {2,2,1,3} and h2:
    /// {2,4,3,3}.
    pub(crate) fn combine_split(&self, f: &Self) -> Result<(Self, Self), Error> {
        let mut counters: IndexMap<F, usize> = IndexMap::with_capacity(self.len());

        // Creates buckets out of the values in t
        for element in &self.0 {
            if let Some(v) = counters.get_mut(element) {
                *v += 1;
            } else {
                counters.insert(*element, 1);
            }
        }

        // Insert elements of f into buckets and checks that elements of f are
        // in t
        for element in &f.0 {
            if let Some(entry) = counters.get_mut(element) {
                *entry += 1;
            } else {
                return Err(Error::ElementNotIndexed);
            }
        }

        let n_elems = self.len() + f.len();
        let half_len = n_elems / 2;
        let mut evens = Vec::with_capacity(half_len + (n_elems % 2));
        let mut odds = Vec::with_capacity(half_len);
        let mut parity = false;
        for (elem, count) in counters {
            let half_count = count / 2;
            evens.extend(vec![elem; half_count]);
            odds.extend(vec![elem; half_count]);
            if count % 2 == 1 {
                if parity {
                    odds.push(elem);
                    parity = false;
                } else {
                    evens.push(elem);
                    parity = true;
                }
            }
        }

        Ok((Self(evens), Self(odds)))
    }

    /// Checks whether one mutltiset is a subset of another.
    /// This function will be used to check if the all elements
    /// in set f, from the paper, are contained inside t.
    ///
    /// Unoptimized function only used for testing
    #[cfg(test)]
    pub(crate) fn contains_all(&self, other: &Self) -> bool {
        other.0.iter().all(|item| self.contains(item))
    }

    /// Checks if an element is in the MultiSet
    pub fn contains(&self, entry: &F) -> bool {
        self.0.contains(entry)
    }

    /// Treats each element in the multiset as evaluation points
    /// Computes IFFT of the set of evaluation points
    /// and returns the coefficients as a Polynomial data structure
    pub(crate) fn into_polynomial<D>(self, domain: &D) -> DensePolynomial<F>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        poly_from_evals(domain, self.0)
    }
}

impl<F> From<&[F]> for MultiSet<F>
where
    F: Field,
{
    #[inline]
    fn from(slice: &[F]) -> Self {
        Self(slice.to_vec())
    }
}

impl<F: Field> Deref for MultiSet<F> {
    type Target = [F];

    fn deref(&self) -> &[F] {
        &self.0
    }
}

impl<F: Field> DerefMut for MultiSet<F> {
    fn deref_mut(&mut self) -> &mut [F] {
        &mut self.0
    }
}

impl<F: Field> FromIterator<F> for MultiSet<F> {
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = F>,
    {
        Self(Vec::from_iter(iter))
    }
}

#[cfg(feature = "parallel")]
impl<F: Field> FromParallelIterator<F> for MultiSet<F> {
    #[inline]
    fn from_par_iter<I>(iter: I) -> Self
    where
        I: IntoParallelIterator<Item = F>,
    {
        Self(Vec::from_par_iter(iter))
    }
}

/// Elementwise addtion
impl<F> Add for MultiSet<F>
where
    F: Field,
{
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        self.0
            .into_iter()
            .zip(other.0)
            .map(|(x, y)| x + y)
            .collect()
    }
}

/// Elementwise multiplication
impl<F> Mul<MultiSet<F>> for MultiSet<F>
where
    F: Field,
{
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        self.0
            .into_iter()
            .zip(other.0)
            .map(|(x, y)| x * y)
            .collect()
    }
}

/// Multiplication with a field element
impl<F> Mul<F> for MultiSet<F>
where
    F: Field,
{
    type Output = Self;
    fn mul(self, elem: F) -> Self::Output {
        self.0.into_iter().map(|x| x * elem).collect()
    }
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;

    use crate::batch_test_field;
    use super::*;

    fn test_combine_split<F: Field>() {
        // t = {0, 1, 2, 3, 4, 5, 6}
        let mut t = MultiSet::new();
        t.push(F::zero());
        t.push(F::one());
        t.push(F::from(2u32));
        t.push(F::from(3u32));
        t.push(F::from(4u32));
        t.push(F::from(5u32));
        t.push(F::from(6u32));

        // f = {3, 6, 0, 5, 4, 3, 2, 0, 0, 1, 2}
        let mut f = MultiSet::new();
        f.push(F::from(3u32));
        f.push(F::from(6u32));
        f.push(F::from(0u32));
        f.push(F::from(5u32));
        f.push(F::from(4u32));
        f.push(F::from(3u32));
        f.push(F::from(2u32));
        f.push(F::from(0u32));
        f.push(F::from(0u32));
        f.push(F::from(1u32));
        f.push(F::from(2u32));

        assert!(t.contains_all(&f));

        // combined: {0, 0, 0, 0, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 5, 5, 6, 6}
        // evens:    {0,    0,    1,    2,    2,    3,    4,    5,    6,  }
        // odds:     {   0,    0,    1,    2,    3,    3,    4,    5,    6}
        let (h1, h2) = t.combine_split(&f).unwrap();

        let evens = MultiSet(vec![
            F::zero(),
            F::zero(),
            F::one(),
            F::from(2u32),
            F::from(2u32),
            F::from(3u32),
            F::from(4u32),
            F::from(5u32),
            F::from(6u32),
        ]);
        let odds = MultiSet(vec![
            F::zero(),
            F::zero(),
            F::one(),
            F::from(2u32),
            F::from(3u32),
            F::from(3u32),
            F::from(4u32),
            F::from(5u32),
            F::from(6u32),
        ]);

        assert_eq!(evens, h1);
        assert_eq!(odds, h2);
    }

    batch_test_field!(
        Bn254,
        [test_combine_split],
        []
    );

    batch_test_field!(
        Bls12_377,
        [test_combine_split],
        []
    );

    batch_test_field!(
        Bls12_381,
        [test_combine_split],
        []
    );
}
