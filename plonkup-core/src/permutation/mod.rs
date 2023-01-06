// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Permutations

pub(crate) mod constants;

use ark_std::cfg_iter;
use ark_ff::{FftField, Field};
use ark_poly::{domain::EvaluationDomain, univariate::DensePolynomial};
use constants::{K1, K2};
use itertools::Itertools;
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{constraint_system::Variable, util::poly_from_evals};

/// Stores the data for a specific wire in an arithmetic circuit
/// This data is the gate index and the type of wire
/// Left(1) signifies that this wire belongs to the first gate and is the left
/// wire
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WireData {
    /// Left Wire of n'th gate
    Left(usize),
    /// Right Wire of n'th gate
    Right(usize),
    /// Output Wire of n'th gate
    Output(usize),
}

/// Permutation provides the necessary state information and functions
/// to create the permutation polynomial. In the literature, Z(X) is the
/// "accumulator", this is what this codebase calls the permutation polynomial.
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct Permutation(Vec<Vec<WireData>>);

impl Permutation {
    /// Creates a Permutation struct with an expected capacity of zero.
    pub(crate) fn new() -> Self {
        Permutation::with_capacity(0)
    }

    /// Creates a Permutation struct with an expected capacity of `n`.
    pub(crate) fn with_capacity(expected_size: usize) -> Self {
        let mut perm = Self(Vec::with_capacity(expected_size));
        // For variable zero
        perm.0.push(Vec::with_capacity(64usize));
        // For variable one
        perm.0.push(Vec::with_capacity(32usize));

        perm
    }

    /// Creates a new [`Variable`] by incrementing the index of the
    /// `variable_map`. This is correct as whenever we add a new [`Variable`]
    /// into the system It is always allocated in the `variable_map`.
    pub fn new_variable(&mut self) -> Variable {
        // Generate the Variable
        let var = Variable::Var(self.0.len() - 2);

        // Allocate space for the Variable on the variable_map
        // Each vector is initialised with a capacity of 16.
        // This number is a best guess estimate.
        self.0.push(Vec::with_capacity(16usize));

        var
    }

    /// Maps a set of [`Variable`]s (a,b,c,d) to a set of [`Wire`](WireData)s
    /// (left, right, out, fourth) with the corresponding gate index
    pub fn add_variables_to_map(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        gate_index: usize,
    ) {
        // Map each variable to the wire it is associated with
        // This essentially tells us that:
        self.add_variable_to_map(w_l, WireData::Left(gate_index));
        self.add_variable_to_map(w_r, WireData::Right(gate_index));
        self.add_variable_to_map(w_o, WireData::Output(gate_index));
    }

    ///
    fn add_variable_to_map(&mut self, var: Variable, wire_data: WireData) {
        // NOTE: Since we always allocate space for the Vec of WireData when a
        // `Variable` is added to the variable_map, this should never fail.
        let i = match var {
            Variable::Zero => 0,
            Variable::One => 1,
            Variable::Var(i) => i + 2,
        };
        self.0[i].push(wire_data);
    }
    
    /// Performs shift by one permutation and computes `sigma1`, `sigma2` and
    /// `sigma3` permutations from the variable maps.
    fn compute_sigma_permutations(
        &mut self,
        n: usize,
    ) -> (Vec<WireData>, Vec<WireData>, Vec<WireData>) {
        let mut sigma1 = (0..n).map(WireData::Left).collect_vec();
        let mut sigma2 = (0..n).map(WireData::Right).collect_vec();
        let mut sigma3 = (0..n).map(WireData::Output).collect_vec();

        for wire_datas in self.0.iter() {
            // Gets the data for each wire assosciated with this variable
            for (wire_index, current_wire) in wire_datas.iter().enumerate() {
                // Fetch index of the next wire, if it is the last element
                // We loop back around to the beginning
                let next_index = if wire_index == wire_datas.len() - 1 {
                    0
                } else {
                    wire_index + 1
                };

                // Fetch the next wire
                let next_wire = wire_datas[next_index];
                // Map current wire to next wire
                match current_wire {
                    WireData::Left(i) => sigma1[*i] = next_wire,
                    WireData::Right(i) => sigma2[*i] = next_wire,
                    WireData::Output(i) => sigma3[*i] = next_wire,
                };
            }
        }

        (sigma1, sigma2, sigma3)
    }

    fn compute_sigma_evals<F: Field>(
        &self,
        sigma_mapping: &[WireData],
        roots: &[F],
    ) -> Vec<F> {
        cfg_iter!(sigma_mapping)
            .map(|x| match x {
                WireData::Left(index) => {
                    roots[*index]
                }
                WireData::Right(index) => {
                    K1::<F>() * roots[*index]
                }
                WireData::Output(index) => {
                    K2::<F>() * roots[*index]
                }
            })
            .collect()
    }

    /// Computes the sigma polynomials which are used to build the permutation
    /// polynomial.
    pub(crate) fn compute_all_sigma_evals<F: FftField>(
        &mut self,
        n: usize,
        roots: &[F],
    ) -> (Vec<F>, Vec<F>, Vec<F>) {
        // Compute sigma mappings
        let (sigma1, sigma2, sigma3) =
            self.compute_sigma_permutations(n);

        assert_eq!(sigma1.len(), n);
        assert_eq!(sigma2.len(), n);
        assert_eq!(sigma3.len(), n);

        // define the sigma permutations using two non quadratic residues
        let sigma1 = self.compute_sigma_evals(&sigma1, roots);
        let sigma2 = self.compute_sigma_evals(&sigma2, roots);
        let sigma3 = self.compute_sigma_evals(&sigma3, roots);

        (sigma1, sigma2, sigma3)
    }
}

///
pub(crate) fn compute_z1_poly<F, D>(
    domain: &D,
    beta: F,
    gamma: F,
    a: &[F],
    b: &[F],
    c: &[F],
    sigma1: &[F],
    sigma2: &[F],
    sigma3: &[F],
) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    let n = domain.size();
    assert_eq!(a.len(), n);
    assert_eq!(b.len(), n);
    assert_eq!(c.len(), n);
    assert_eq!(sigma1.len(), n);
    assert_eq!(sigma2.len(), n);
    assert_eq!(sigma3.len(), n);

    let roots = domain.elements().collect_vec();

    // Transpose wires and sigma values to get "rows" in the form [wl_i,
    // wr_i, wo_i, ... ] where each row contains the wire and sigma
    // values for a single gate
    #[cfg(not(feature = "parallel"))]
    let wires = itertools::izip!(a, b, c);
    #[cfg(feature = "parallel")]
    let wires = crate::par_izip!(
        a.par_iter(),
        b.par_iter(),
        c.par_iter(),
    );

    #[cfg(not(feature = "parallel"))]
    let sigmas = itertools::izip!(sigma1, sigma2, sigma3);
    #[cfg(feature = "parallel")]
    let sigmas = crate::par_izip!(
        sigma1.par_iter(),
        sigma2.par_iter(),
        sigma3.par_iter(),
    );

    #[cfg(not(feature = "parallel"))]
    let product = itertools::izip!(roots, sigmas, wires);
    #[cfg(feature = "parallel")]
    let product = crate::par_izip!(roots, sigmas, wires);

    let product: Vec<_> = product
        .take(n - 1)
        .map(|(root, sigma, wire)| {
            let numinator = (beta * root + wire.0 + gamma)
                * (K1::<F>() * beta * root + wire.1 + gamma)
                * (K2::<F>() * beta * root + wire.2 + gamma);
            let dominator = (beta * sigma.0 + wire.0 + gamma)
                * (beta * sigma.1 + wire.1 + gamma)
                * (beta * sigma.2 + wire.2 + gamma);
            
            numinator * dominator.inverse().unwrap()
        })
        .collect();

    let mut z1_evals = Vec::with_capacity(n);
    // First element is one
    let mut state = F::one();
    z1_evals.push(state);
    // Accumulate by successively multiplying the scalars
    for s in product {
        state *= s;
        z1_evals.push(state);
    }

    poly_from_evals(domain, z1_evals)
}

#[cfg(test)]
mod test {
    use ark_ff::FftField;
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_377::Bls12_377;
    use ark_poly::{GeneralEvaluationDomain, Polynomial};
    use ark_std::test_rng;
    use itertools::izip;

    use crate::{
        constraint_system::{ConstraintSystem, SetupComposer},
        util::EvaluationDomainExt,
        batch_test_field,
    };
    use super::*;

    fn test_compute_sigma_permutations<F: FftField>() {
        let cs = ConstraintSystem::<F>::new(true);
        let mut composer: SetupComposer<_> = cs.composer.into();

        // x1 * x4 = x2
        // x1 + x3 = x2
        // x1 + x2 = 2*x3
        // x3 * x4 = 2*x2
        let x1 = composer.perm.new_variable();
        let x2 = composer.perm.new_variable();
        let x3 = composer.perm.new_variable();
        let x4 = composer.perm.new_variable();

        composer.perm.add_variables_to_map(x1, x4, x2, 0);
        composer.perm.add_variables_to_map(x1, x3, x2, 1);
        composer.perm.add_variables_to_map(x1, x2, x3, 2);
        composer.perm.add_variables_to_map(x3, x4, x2, 3);

        let (sigma1, sigma2, sigma3) =
            composer.perm.compute_sigma_permutations(4);

        // sigma1
        //  l(0) -> l(1) --- x1
        //  l(1) -> l(2) --- x1
        //  l(2) -> l(0) --- x1
        //  l(3) -> r(1) --- x3
        assert_eq!(sigma1[0], WireData::Left(1));
        assert_eq!(sigma1[1], WireData::Left(2));
        assert_eq!(sigma1[2], WireData::Left(0));
        assert_eq!(sigma1[3], WireData::Right(1));

        // sigma2
        //  r(0) -> r(3) --- x4
        //  r(1) -> o(2) --- x3
        //  r(2) -> o(3) --- x2
        //  r(3) -> r(0) --- x4
        assert_eq!(sigma2[0], WireData::Right(3));
        assert_eq!(sigma2[1], WireData::Output(2));
        assert_eq!(sigma2[2], WireData::Output(3));
        assert_eq!(sigma2[3], WireData::Right(0));

        // sigma3
        //  o(0) -> o(1) --- x2
        //  o(1) -> r(2) --- x2
        //  o(2) -> l(3) --- x3
        //  o(3) -> o(0) --- x2
        assert_eq!(sigma3[0], WireData::Output(1));
        assert_eq!(sigma3[1], WireData::Right(2));
        assert_eq!(sigma3[2], WireData::Left(3));
        assert_eq!(sigma3[3], WireData::Output(0));
    }

    fn test_compute_z1_poly<F: FftField>() {
        let rng = &mut test_rng();

        let cs = ConstraintSystem::<F>::new(true);
        let mut composer: SetupComposer<_> = cs.composer.into();

        // x1 * x4 = x2
        // x1 + x3 = x2
        // x1 + x2 = 2*x3
        // x3 * x4 = 2*x2
        let x1 = composer.perm.new_variable();
        let x2 = composer.perm.new_variable();
        let x3 = composer.perm.new_variable();
        let x4 = composer.perm.new_variable();

        composer.perm.add_variables_to_map(x1, x4, x2, 0);
        composer.perm.add_variables_to_map(x1, x3, x2, 1);
        composer.perm.add_variables_to_map(x1, x2, x3, 2);
        composer.perm.add_variables_to_map(x3, x4, x2, 3);

        let domain = GeneralEvaluationDomain::new(4).unwrap();
        let roots = domain.elements().collect_vec();
        let (sigma1, sigma2, sigma3) =
            composer.perm.compute_all_sigma_evals(4, &roots);
        
        let x1 = F::from(4u32);
        let x2 = F::from(12u32);
        let x3 = F::from(8u32);
        let x4 = F::from(3u32);

        let beta = F::rand(rng);
        let gamma = F::rand(rng);
        let a = vec![x1, x1, x1, x3];
        let b = vec![x4, x3, x2, x4];
        let c = vec![x2, x2, x3, x2];
        let z1_poly = compute_z1_poly(
            &domain,
            beta,
            gamma,
            &a,
            &b,
            &c,
            &sigma1,
            &sigma2,
            &sigma3,
        );

        let omega = domain.group_gen();
        izip!(roots.iter(), a, b, c, sigma1, sigma2, sigma3)
            .for_each(|(root, a, b, c, s1, s2, s3)| {
                let part_1 = (beta * root + a + gamma)
                    * (beta * K1::<F>() * root + b + gamma)
                    * (beta * K2::<F>() * root + c + gamma)
                    * z1_poly.evaluate(root);
                let part_2 = (beta * s1 + a + gamma)
                    * (beta * s2 + b + gamma)
                    * (beta * s3 + c + gamma)
                    * z1_poly.evaluate(&(omega * root));
                
                assert_eq!(part_1, part_2);
            });

        let root_0 = roots[0];
        assert_eq!(z1_poly.evaluate(&root_0), F::one());
    }

    batch_test_field!(
        Bn254,
        [
            test_compute_sigma_permutations,
            test_compute_z1_poly
        ],
        []
    );

    batch_test_field!(
        Bls12_377,
        [
            test_compute_sigma_permutations,
            test_compute_z1_poly
        ],
        []
    );

    batch_test_field!(
        Bls12_381,
        [
            test_compute_sigma_permutations,
            test_compute_z1_poly
        ],
        []
    );
}
