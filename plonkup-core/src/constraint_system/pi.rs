// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.

//! Public Inputs of the circuit. This values are available for the
//! [`super::Prover`] and [`super::Verifier`].
//!
//! This module contains the implementation of the [`PublicInputs`] struct and
//! all the basic manipulations such as inserting new values and getting the
//! public inputs in evaluation or coefficient form.

use alloc::collections::{BTreeMap, BTreeSet};
use ark_ff::{FftField, Field};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain};
use ark_serialize::*;

use crate::util::poly_from_evals;

///
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PublicPositions(BTreeSet<usize>);

impl PublicPositions {
    /// Creates a new struct for [`PublicInputs`].
    pub(crate) fn new() -> Self {
        Self(BTreeSet::new())
    }

    ///
    pub fn size(&self) -> usize {
        self.0.len()
    }
    
    /// Inserts public input data that can be converted to one or more field
    /// elements starting at a given position.
    /// Returns the number of field elements occupied by the input or
    /// [`Error::InvalidPublicInputValue`] if the input could not be converted.
    pub fn add_input(&mut self, pos: usize) {
        assert!(self.0.insert(pos));
    }

    /// Returns the position of non-zero PI values.
    pub fn get_pos(&self) -> impl Iterator<Item = &usize> {
        self.0.iter()
    }
}

///  Public Inputs
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, Hash, PartialEq)]
pub struct PublicInputs<F: Field>(BTreeMap<usize, F>);

impl<F: Field> PublicInputs<F> {
    /// Creates a new struct for [`PublicInputs`].
    pub(crate) fn new() -> Self {
        Self(BTreeMap::new())
    }

    ///
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Inserts public input data that can be converted to one or more field
    /// elements starting at a given position.
    /// Returns the number of field elements occupied by the input or
    /// [`Error::InvalidPublicInputValue`] if the input could not be converted.
    pub fn add_input(&mut self, pos: usize, item: F) {
        assert!(self.0.insert(pos, item).is_none());
    }

    /// Returns the public inputs as a vector of `n` evaluations.
    /// The provided `n` must be a power of 2.
    pub(crate) fn as_evals(&self, n: usize) -> Vec<F> {
        let mut pi = vec![F::zero(); n];
        for (pos, eval) in self.0.iter() {
            pi[*pos] = *eval;
        }

        pi
    }

    /// Returns the public inputs as a vector of `n` evaluations.
    /// The provided `n` must be a power of 2.
    pub(crate) fn to_dense_poly<D>(&self, domain: &D) -> DensePolynomial<F>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        let n = domain.size();
        let evals = self.as_evals(n);
        poly_from_evals(domain, evals)
    }

    /// Returns the position of non-zero PI values.
    pub fn get_pos(&self) -> impl Iterator<Item = &usize> {
        self.0.keys()
    }

    /// Returns the non-zero PI values.
    pub fn get_vals(&self) -> impl Iterator<Item = &F> {
        self.0.values()
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::batch_field_test;
//     use ark_bls12_377::Fr as Bls12_377_scalar_field;
//     use ark_bls12_381::Fr as Bls12_381_scalar_field;

//     // Checks PublicInputs representation is not affected by insertion order
//     // or extra zeros.
//     fn test_pi_unique_repr<F>()
//     where
//         F: FftField,
//     {
//         let mut pi_1 = PublicInputs::new();

//         pi_1.insert(2, F::from(2u64));
//         pi_1.insert(5, F::from(5u64));
//         pi_1.insert(6, F::from(6u64));

//         let mut pi_2 = PublicInputs::new();

//         pi_2.insert(6, F::from(6u64));
//         pi_2.insert(5, F::from(5u64));
//         pi_2.insert(2, F::from(2u64));

//         pi_2.insert(0, F::zero());
//         pi_2.insert(1, F::zero());
//         assert_eq!(pi_1, pi_2);
//     }

//     // Checks PublicInputs does not allow to override already inserted values.
//     fn test_pi_dup_insertion<F>()
//     where
//         F: FftField,
//     {
//         let mut pi_1 = PublicInputs::new();

//         pi_1.insert(2, F::from(2u64));
//         pi_1.insert(5, F::from(5u64));
//         pi_1.insert(5, F::from(2u64));
//     }

//     // Bls12-381 tests
//     batch_field_test!(
//         [
//             test_pi_unique_repr
//         ],
//         [
//            test_pi_dup_insertion
//         ] => Bls12_381_scalar_field
//     );

//     // Bls12-377 tests
//     batch_field_test!(
//         [
//             test_pi_unique_repr
//         ],
//         [
//            test_pi_dup_insertion
//         ] => Bls12_377_scalar_field
//     );
// }
