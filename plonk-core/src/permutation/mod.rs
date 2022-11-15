// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Permutations

pub(crate) mod constants;

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
        Self(Vec::with_capacity(expected_size))
    }

    /// Creates a new [`Variable`] by incrementing the index of the
    /// `variable_map`. This is correct as whenever we add a new [`Variable`]
    /// into the system It is always allocated in the `variable_map`.
    pub fn new_variable(&mut self) -> Variable {
        // Generate the Variable
        let var = Variable::Var(self.0.len());

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
        a: Variable,
        b: Variable,
        c: Variable,
        gate_index: usize,
    ) {
        // Map each variable to the wire it is associated with
        // This essentially tells us that:
        self.add_variable_to_map(a, WireData::Left(gate_index));
        self.add_variable_to_map(b, WireData::Right(gate_index));
        self.add_variable_to_map(c, WireData::Output(gate_index));
    }

    ///
    fn add_variable_to_map(&mut self, var: Variable, wire_data: WireData) {
        // NOTE: Since we always allocate space for the Vec of WireData when a
        // `Variable` is added to the variable_map, this should never fail.
        if let Variable::Var(i) = var {
            self.0[i].push(wire_data);
        }
    }
    
    /// Performs shift by one permutation and computes `sigma1`, `sigma2` and
    /// `sigma3` permutations from the variable maps.
    fn compute_sigma_permutations(
        &mut self,
        n: usize,
    ) -> (Vec<WireData>, Vec<WireData>, Vec<WireData>) {
        let mut sigma1 = (0..n).map(WireData::Left).collect::<Vec<_>>();
        let mut sigma2 = (0..n).map(WireData::Right).collect::<Vec<_>>();
        let mut sigma3 = (0..n).map(WireData::Output).collect::<Vec<_>>();

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
                    WireData::Left(index) => sigma1[*index] = next_wire,
                    WireData::Right(index) => sigma2[*index] = next_wire,
                    WireData::Output(index) => sigma3[*index] = next_wire,
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
        sigma_mapping
            .iter()
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
    pub(crate) fn compute_all_sigma_evals<F, D>(
        &mut self,
        n: usize,
        domain: &D,
    ) -> (Vec<F>, Vec<F>, Vec<F>)
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        // Compute sigma mappings
        let sigmas = self.compute_sigma_permutations(n);

        assert_eq!(sigmas.0.len(), n);
        assert_eq!(sigmas.1.len(), n);
        assert_eq!(sigmas.2.len(), n);

        let roots = domain.elements().collect_vec();

        // define the sigma permutations using two non quadratic residues
        let sigma1 = self.compute_sigma_evals(&sigmas.0, &roots);
        let sigma2 = self.compute_sigma_evals(&sigmas.1, &roots);
        let sigma3 = self.compute_sigma_evals(&sigmas.2, &roots);

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
            let numinator = (root * beta + wire.0 + gamma)
                * (root * K1::<F>() * beta + wire.1 + gamma)
                * (root * K1::<F>() * beta + wire.2 + gamma);
            let dominator = (root * sigma.0 + wire.0 + gamma)
                * (root * sigma.1 + wire.1 + gamma)
                * (root * sigma.2 + wire.2 + gamma);
            
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

///
pub(crate) fn compute_z2_poly<F, D>(
    domain: &D,
    delta: F,
    epsilon: F,
    f: &[F],
    t: &[F],
    h1: &[F],
    h2: &[F],
) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    let n = domain.size();

    assert_eq!(f.len(), n);
    assert_eq!(t.len(), n);
    assert_eq!(h1.len(), n);
    assert_eq!(h2.len(), n);

    #[cfg(not(feature = "parallel"))]
    let t_next = t.iter().skip(1);
    #[cfg(feature = "parallel")]
    let t_next = t.par_iter().skip(1);

    #[cfg(not(feature = "parallel"))]
    let h1_next = h1.iter().skip(1);
    #[cfg(feature = "parallel")]
    let h1_next = h1.par_iter().skip(1);

    let one_plus_delta = F::one() + delta;
    let epsilon_one_plus_delta = epsilon * one_plus_delta;

    #[cfg(not(feature = "parallel"))]
    let product = itertools::izip!(f, t, t_next, h1, h1_next, h2);
    #[cfg(feature = "parallel")]
    let product = crate::par_izip!(
        f.par_iter(),
        t.par_iter(),
        t_next,
        h1.par_iter(),
        h1_next,
        h2.par_iter(),
    );

    let product: Vec<_> = product
        .take(n - 1)
        .map(|(f, t, t_next, h1, h1_next, h2)| {
            let numinator = one_plus_delta
                * (epsilon + f)
                * (epsilon_one_plus_delta + t + (delta * t_next));
            let dominator = (epsilon_one_plus_delta + h1 + (*h2 * delta))
                * (epsilon_one_plus_delta + h2 + (*h1_next * delta));

            numinator * dominator.inverse().unwrap()
        })
        .collect();

    let mut z2_evals = Vec::with_capacity(n);
    let mut state = F::one();
    z2_evals.push(state);
    for s in product {
        state *= s;
        z2_evals.push(state);
    }

    poly_from_evals(domain, z2_evals)
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{batch_test_field, batch_test_field_params};
//     use crate::{
//         constraint_system::ConstraintSystem, util::EvaluationDomainExt,
//     };
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use ark_ec::TEModelParameters;
//     use ark_ff::{Field, PrimeField};
//     use ark_poly::univariate::DensePolynomial;
//     use ark_poly::Polynomial;
//     use rand_core::OsRng;

//     fn test_multizip_permutation_poly<F, P>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//     {
//         let mut cs: ConstraintSystem<F, P> =
//             ConstraintSystem::<F, P>::with_expected_size(4);

//         let zero = F::zero();
//         let one = F::one();
//         let two = one + one;

//         let x1 = cs.add_input(F::from(4u64));
//         let x2 = cs.add_input(F::from(12u64));
//         let x3 = cs.add_input(F::from(8u64));
//         let x4 = cs.add_input(F::from(3u64));

//         // x1 * x4 = x2
//         cs.poly_gate(x1, x4, x2, one, zero, zero, -one, zero, None);

//         // x1 + x3 = x2
//         cs.poly_gate(x1, x3, x2, zero, one, one, -one, zero, None);

//         // x1 + x2 = 2*x3
//         cs.poly_gate(x1, x2, x3, zero, one, one, -two, zero, None);

//         // x3 * x4 = 2*x2
//         cs.poly_gate(x3, x4, x2, one, zero, zero, -two, zero, None);

//         let domain =
//             GeneralEvaluationDomain::<F>::new(cs.circuit_bound()).unwrap();

//         let pad = vec![F::zero(); domain.size() - cs.w_l.len()];
//         let mut w_l_scalar: Vec<F> =
//             cs.w_l.iter().map(|v| cs.var_map[v]).collect();
//         let mut w_r_scalar: Vec<F> =
//             cs.w_r.iter().map(|v| cs.var_map[v]).collect();
//         let mut w_o_scalar: Vec<F> =
//             cs.w_o.iter().map(|v| cs.var_map[v]).collect();
//         let mut w_4_scalar: Vec<F> =
//             cs.w_4.iter().map(|v| cs.var_map[v]).collect();

//         w_l_scalar.extend(&pad);
//         w_r_scalar.extend(&pad);
//         w_o_scalar.extend(&pad);
//         w_4_scalar.extend(&pad);

//         let sigmas: Vec<Vec<F>> = cs
//             .perm
//             .compute_sigma_permutations(cs.circuit_bound())
//             .iter()
//             .map(|wd| cs.perm.compute_permutation_lagrange(wd, &domain))
//             .collect();

//         let beta = F::rand(&mut OsRng);
//         let gamma = F::rand(&mut OsRng);

//         let sigma_polys: Vec<DensePolynomial<F>> = sigmas
//             .iter()
//             .map(|v| DensePolynomial::from_coefficients_vec(domain.ifft(v)))
//             .collect();

//         let mz = cs.perm.compute_permutation_poly(
//             &domain,
//             (&w_l_scalar, &w_r_scalar, &w_o_scalar, &w_4_scalar),
//             beta,
//             gamma,
//             (
//                 &sigma_polys[0],
//                 &sigma_polys[1],
//                 &sigma_polys[2],
//                 &sigma_polys[3],
//             ),
//         );

//         let old_z = DensePolynomial::from_coefficients_vec(domain.ifft(
//             &cs.perm.compute_fast_permutation_poly(
//                 &domain,
//                 &w_l_scalar,
//                 &w_r_scalar,
//                 &w_o_scalar,
//                 &w_4_scalar,
//                 beta,
//                 gamma,
//                 (
//                     &sigma_polys[0],
//                     &sigma_polys[1],
//                     &sigma_polys[2],
//                     &sigma_polys[3],
//                 ),
//             ),
//         ));

//         assert_eq!(mz, old_z);
//     }

//     #[test]
//     #[allow(non_snake_case)]
//     fn test_permutation_format() {
//         let mut perm: Permutation = Permutation::new();

//         let num_variables = 10u8;
//         for i in 0..num_variables {
//             let var = perm.new_variable();
//             assert_eq!(var.0, i as usize);
//             assert_eq!(perm.variable_map.len(), (i as usize) + 1);
//         }

//         let var_one = perm.new_variable();
//         let var_two = perm.new_variable();
//         let var_three = perm.new_variable();

//         let gate_size = 100;
//         for i in 0..gate_size {
//             perm.add_variables_to_map(var_one, var_one, var_two, var_three, i);
//         }

//         // Check all gate_indices are valid
//         for (_, wire_data) in perm.variable_map.iter() {
//             for wire in wire_data.iter() {
//                 match wire {
//                     WireData::Left(index)
//                     | WireData::Right(index)
//                     | WireData::Output(index)
//                     | WireData::Fourth(index) => assert!(*index < gate_size),
//                 };
//             }
//         }
//     }

//     fn test_permutation_compute_sigmas_only_left_wires<F: FftField>() {
//         let mut perm = Permutation::new();

//         let var_zero = perm.new_variable();
//         let var_two = perm.new_variable();
//         let var_three = perm.new_variable();
//         let var_four = perm.new_variable();
//         let var_five = perm.new_variable();
//         let var_six = perm.new_variable();
//         let var_seven = perm.new_variable();
//         let var_eight = perm.new_variable();
//         let var_nine = perm.new_variable();

//         let num_wire_mappings = 4;

//         // Add four wire mappings
//         perm.add_variables_to_map(var_zero, var_zero, var_five, var_nine, 0);
//         perm.add_variables_to_map(var_zero, var_two, var_six, var_nine, 1);
//         perm.add_variables_to_map(var_zero, var_three, var_seven, var_nine, 2);
//         perm.add_variables_to_map(var_zero, var_four, var_eight, var_nine, 3);

//         /*
//         var_zero = {L0, R0, L1, L2, L3}
//         var_two = {R1}
//         var_three = {R2}
//         var_four = {R3}
//         var_five = {O0}
//         var_six = {O1}
//         var_seven = {O2}
//         var_eight = {O3}
//         var_nine = {F0, F1, F2, F3}
//         Left_sigma = {R0, L2, L3, L0}
//         Right_sigma = {L1, R1, R2, R3}
//         Out_sigma = {O0, O1, O2, O3}
//         Fourth_sigma = {F1, F2, F3, F0}
//         */
//         let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
//         let left_sigma = &sigmas[0];
//         let right_sigma = &sigmas[1];
//         let out_sigma = &sigmas[2];
//         let fourth_sigma = &sigmas[3];

//         // Check the left sigma polynomial
//         assert_eq!(left_sigma[0], WireData::Right(0));
//         assert_eq!(left_sigma[1], WireData::Left(2));
//         assert_eq!(left_sigma[2], WireData::Left(3));
//         assert_eq!(left_sigma[3], WireData::Left(0));

//         // Check the right sigma polynomial
//         assert_eq!(right_sigma[0], WireData::Left(1));
//         assert_eq!(right_sigma[1], WireData::Right(1));
//         assert_eq!(right_sigma[2], WireData::Right(2));
//         assert_eq!(right_sigma[3], WireData::Right(3));

//         // Check the output sigma polynomial
//         assert_eq!(out_sigma[0], WireData::Output(0));
//         assert_eq!(out_sigma[1], WireData::Output(1));
//         assert_eq!(out_sigma[2], WireData::Output(2));
//         assert_eq!(out_sigma[3], WireData::Output(3));

//         // Check the output sigma polynomial
//         assert_eq!(fourth_sigma[0], WireData::Fourth(1));
//         assert_eq!(fourth_sigma[1], WireData::Fourth(2));
//         assert_eq!(fourth_sigma[2], WireData::Fourth(3));
//         assert_eq!(fourth_sigma[3], WireData::Fourth(0));

//         let domain =
//             GeneralEvaluationDomain::<F>::new(num_wire_mappings).unwrap();
//         let w = domain.group_gen();
//         let w_squared = w.pow(&[2, 0, 0, 0]);
//         let w_cubed = w.pow(&[3, 0, 0, 0]);

//         // Check the left sigmas have been encoded properly
//         // Left_sigma = {R0, L2, L3, L0}
//         // Should turn into {1 * K1, w^2, w^3, 1}
//         let encoded_left_sigma =
//             perm.compute_permutation_lagrange(left_sigma, &domain);
//         assert_eq!(encoded_left_sigma[0], F::one() * K1::<F>());
//         assert_eq!(encoded_left_sigma[1], w_squared);
//         assert_eq!(encoded_left_sigma[2], w_cubed);
//         assert_eq!(encoded_left_sigma[3], F::one());

//         // Check the right sigmas have been encoded properly
//         // Right_sigma = {L1, R1, R2, R3}
//         // Should turn into {w, w * K1, w^2 * K1, w^3 * K1}
//         let encoded_right_sigma =
//             perm.compute_permutation_lagrange(right_sigma, &domain);
//         assert_eq!(encoded_right_sigma[0], w);
//         assert_eq!(encoded_right_sigma[1], w * K1::<F>());
//         assert_eq!(encoded_right_sigma[2], w_squared * K1::<F>());
//         assert_eq!(encoded_right_sigma[3], w_cubed * K1::<F>());

//         // Check the output sigmas have been encoded properly
//         // Out_sigma = {O0, O1, O2, O3}
//         // Should turn into {1 * K2, w * K2, w^2 * K2, w^3 * K2}

//         let encoded_output_sigma =
//             perm.compute_permutation_lagrange(out_sigma, &domain);
//         assert_eq!(encoded_output_sigma[0], F::one() * K2::<F>());
//         assert_eq!(encoded_output_sigma[1], w * K2::<F>());
//         assert_eq!(encoded_output_sigma[2], w_squared * K2::<F>());
//         assert_eq!(encoded_output_sigma[3], w_cubed * K2::<F>());

//         // Check the fourth sigmas have been encoded properly
//         // Out_sigma = {F1, F2, F3, F0}
//         // Should turn into {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
//         let encoded_fourth_sigma =
//             perm.compute_permutation_lagrange(fourth_sigma, &domain);
//         assert_eq!(encoded_fourth_sigma[0], w * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[1], w_squared * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[2], w_cubed * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[3], K3());

//         let w_l =
//             vec![F::from(2u64), F::from(2u64), F::from(2u64), F::from(2u64)];
//         let w_r = vec![F::from(2_u64), F::one(), F::one(), F::one()];
//         let w_o = vec![F::one(), F::one(), F::one(), F::one()];
//         let w_4 = vec![F::one(), F::one(), F::one(), F::one()];

//         test_correct_permutation_poly(
//             num_wire_mappings,
//             perm,
//             &domain,
//             w_l,
//             w_r,
//             w_o,
//             w_4,
//         );
//     }
//     fn test_permutation_compute_sigmas<F: FftField>() {
//         let mut perm: Permutation = Permutation::new();

//         let var_one = perm.new_variable();
//         let var_two = perm.new_variable();
//         let var_three = perm.new_variable();
//         let var_four = perm.new_variable();

//         let num_wire_mappings = 4;

//         // Add four wire mappings
//         perm.add_variables_to_map(var_one, var_one, var_two, var_four, 0);
//         perm.add_variables_to_map(var_two, var_one, var_two, var_four, 1);
//         perm.add_variables_to_map(var_three, var_three, var_one, var_four, 2);
//         perm.add_variables_to_map(var_two, var_one, var_three, var_four, 3);

//         /*
//         Below is a sketch of the map created by adding the specific variables into the map
//         var_one : {L0,R0, R1, O2, R3 }
//         var_two : {O0, L1, O1, L3}
//         var_three : {L2, R2, O3}
//         var_four : {F0, F1, F2, F3}
//         Left_Sigma : {0,1,2,3} -> {R0,O1,R2,O0}
//         Right_Sigma : {0,1,2,3} -> {R1, O2, O3, L0}
//         Out_Sigma : {0,1,2,3} -> {L1, L3, R3, L2}
//         Fourth_Sigma : {0,1,2,3} -> {F1, F2, F3, F0}
//         */
//         let sigmas = perm.compute_sigma_permutations(num_wire_mappings);
//         let left_sigma = &sigmas[0];
//         let right_sigma = &sigmas[1];
//         let out_sigma = &sigmas[2];
//         let fourth_sigma = &sigmas[3];

//         // Check the left sigma polynomial
//         assert_eq!(left_sigma[0], WireData::Right(0));
//         assert_eq!(left_sigma[1], WireData::Output(1));
//         assert_eq!(left_sigma[2], WireData::Right(2));
//         assert_eq!(left_sigma[3], WireData::Output(0));

//         // Check the right sigma polynomial
//         assert_eq!(right_sigma[0], WireData::Right(1));
//         assert_eq!(right_sigma[1], WireData::Output(2));
//         assert_eq!(right_sigma[2], WireData::Output(3));
//         assert_eq!(right_sigma[3], WireData::Left(0));

//         // Check the output sigma polynomial
//         assert_eq!(out_sigma[0], WireData::Left(1));
//         assert_eq!(out_sigma[1], WireData::Left(3));
//         assert_eq!(out_sigma[2], WireData::Right(3));
//         assert_eq!(out_sigma[3], WireData::Left(2));

//         // Check the fourth sigma polynomial
//         assert_eq!(fourth_sigma[0], WireData::Fourth(1));
//         assert_eq!(fourth_sigma[1], WireData::Fourth(2));
//         assert_eq!(fourth_sigma[2], WireData::Fourth(3));
//         assert_eq!(fourth_sigma[3], WireData::Fourth(0));

//         /*
//         Check that the unique encodings of the sigma polynomials have been computed properly
//         Left_Sigma : {R0,O1,R2,O0}
//             When encoded using w, K1,K2,K3 we have {1 * K1, w * K2, w^2 * K1, 1 * K2}
//         Right_Sigma : {R1, O2, O3, L0}
//             When encoded using w, K1,K2,K3 we have {w * K1, w^2 * K2, w^3 * K2, 1}
//         Out_Sigma : {L1, L3, R3, L2}
//             When encoded using w, K1, K2,K3 we have {w, w^3 , w^3 * K1, w^2}
//         Fourth_Sigma : {0,1,2,3} -> {F1, F2, F3, F0}
//             When encoded using w, K1, K2,K3 we have {w * K3, w^2 * K3, w^3 * K3, 1 * K3}
//         */
//         let domain =
//             GeneralEvaluationDomain::<F>::new(num_wire_mappings).unwrap();
//         let w = domain.group_gen();
//         let w_squared = w.pow(&[2, 0, 0, 0]);
//         let w_cubed = w.pow(&[3, 0, 0, 0]);
//         // check the left sigmas have been encoded properly
//         let encoded_left_sigma =
//             perm.compute_permutation_lagrange(left_sigma, &domain);
//         assert_eq!(encoded_left_sigma[0], K1());
//         assert_eq!(encoded_left_sigma[1], w * K2::<F>());
//         assert_eq!(encoded_left_sigma[2], w_squared * K1::<F>());
//         assert_eq!(encoded_left_sigma[3], F::one() * K2::<F>());

//         // check the right sigmas have been encoded properly
//         let encoded_right_sigma =
//             perm.compute_permutation_lagrange(right_sigma, &domain);
//         assert_eq!(encoded_right_sigma[0], w * K1::<F>());
//         assert_eq!(encoded_right_sigma[1], w_squared * K2::<F>());
//         assert_eq!(encoded_right_sigma[2], w_cubed * K2::<F>());
//         assert_eq!(encoded_right_sigma[3], F::one());

//         // check the output sigmas have been encoded properly
//         let encoded_output_sigma =
//             perm.compute_permutation_lagrange(out_sigma, &domain);
//         assert_eq!(encoded_output_sigma[0], w);
//         assert_eq!(encoded_output_sigma[1], w_cubed);
//         assert_eq!(encoded_output_sigma[2], w_cubed * K1::<F>());
//         assert_eq!(encoded_output_sigma[3], w_squared);

//         // check the fourth sigmas have been encoded properly
//         let encoded_fourth_sigma =
//             perm.compute_permutation_lagrange(fourth_sigma, &domain);
//         assert_eq!(encoded_fourth_sigma[0], w * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[1], w_squared * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[2], w_cubed * K3::<F>());
//         assert_eq!(encoded_fourth_sigma[3], K3());
//     }

//     fn test_basic_slow_permutation_poly<F: FftField>() {
//         let num_wire_mappings = 2;
//         let mut perm = Permutation::new();
//         let domain =
//             GeneralEvaluationDomain::<F>::new(num_wire_mappings).unwrap();

//         let var_one = perm.new_variable();
//         let var_two = perm.new_variable();
//         let var_three = perm.new_variable();
//         let var_four = perm.new_variable();

//         perm.add_variables_to_map(var_one, var_two, var_three, var_four, 0);
//         perm.add_variables_to_map(var_three, var_two, var_one, var_four, 1);

//         let w_l = vec![F::one(), F::from(3u64)];
//         let w_r = vec![F::from(2u64), F::from(2u64)];
//         let w_o = vec![F::from(3u64), F::one()];
//         let w_4 = vec![F::one(), F::one()];

//         test_correct_permutation_poly(
//             num_wire_mappings,
//             perm,
//             &domain,
//             w_l,
//             w_r,
//             w_o,
//             w_4,
//         );
//     }

//     // shifts the polynomials by one root of unity
//     fn shift_poly_by_one<F: Field>(z_coefficients: Vec<F>) -> Vec<F> {
//         let mut shifted_z_coefficients = z_coefficients;
//         shifted_z_coefficients.push(shifted_z_coefficients[0]);
//         shifted_z_coefficients.remove(0);
//         shifted_z_coefficients
//     }

//     fn test_correct_permutation_poly<F: FftField>(
//         n: usize,
//         mut perm: Permutation,
//         domain: &GeneralEvaluationDomain<F>,
//         w_l: Vec<F>,
//         w_r: Vec<F>,
//         w_o: Vec<F>,
//         w_4: Vec<F>,
//     ) {
//         // 0. Generate beta and gamma challenges
//         //
//         let beta = F::rand(&mut OsRng);
//         let gamma = F::rand(&mut OsRng);
//         assert_ne!(gamma, beta);

//         //1. Compute the permutation polynomial using both methods
//         //
//         let (
//             left_sigma_poly,
//             right_sigma_poly,
//             out_sigma_poly,
//             fourth_sigma_poly,
//         ) = perm.compute_sigma_polynomials(n, domain);
//         let (z_vec, numerator_components, denominator_components) = perm
//             .compute_slow_permutation_poly(
//                 domain,
//                 w_l.clone().into_iter(),
//                 w_r.clone().into_iter(),
//                 w_o.clone().into_iter(),
//                 w_4.clone().into_iter(),
//                 &beta,
//                 &gamma,
//                 (
//                     &left_sigma_poly,
//                     &right_sigma_poly,
//                     &out_sigma_poly,
//                     &fourth_sigma_poly,
//                 ),
//             );

//         let fast_z_vec = perm.compute_fast_permutation_poly(
//             domain,
//             &w_l,
//             &w_r,
//             &w_o,
//             &w_4,
//             beta,
//             gamma,
//             (
//                 &left_sigma_poly,
//                 &right_sigma_poly,
//                 &out_sigma_poly,
//                 &fourth_sigma_poly,
//             ),
//         );
//         assert_eq!(fast_z_vec, z_vec);

//         // 2. First we perform basic tests on the permutation vector
//         //
//         // Check that the vector has length `n` and that the first element is
//         // `1`
//         assert_eq!(z_vec.len(), n);
//         assert_eq!(&z_vec[0], &F::one());
//         //
//         // Check that the \prod{f_i} / \prod{g_i} = 1
//         // Where f_i and g_i are the numerator and denominator components in the
//         // permutation polynomial
//         let (mut a_0, mut b_0) = (F::one(), F::one());
//         for n in numerator_components.iter() {
//             a_0 *= n;
//         }
//         for n in denominator_components.iter() {
//             b_0 *= n;
//         }
//         assert_eq!(a_0 * b_0.inverse().unwrap(), F::one());

//         //3. Now we perform the two checks that need to be done on the
//         // permutation polynomial (z)
//         let z_poly =
//             DensePolynomial::<F>::from_coefficients_vec(domain.ifft(&z_vec));
//         //
//         // Check that z(w^{n+1}) == z(1) == 1
//         // This is the first check in the protocol
//         assert_eq!(z_poly.evaluate(&F::one()), F::one());
//         let n_plus_one = domain.elements().last().unwrap() * domain.group_gen();
//         assert_eq!(z_poly.evaluate(&n_plus_one), F::one());
//         //
//         // Check that when z is unblinded, it has the correct degree
//         assert_eq!(z_poly.degree(), n - 1);
//         //
//         // Check relationship between z(X) and z(Xw)
//         // This is the second check in the protocol
//         let roots: Vec<_> = domain.elements().collect();

//         for i in 1..roots.len() {
//             let current_root = roots[i];
//             let next_root = current_root * domain.group_gen();

//             let current_identity_perm_product = &numerator_components[i];
//             assert_ne!(current_identity_perm_product, &F::zero());

//             let current_copy_perm_product = &denominator_components[i];
//             assert_ne!(current_copy_perm_product, &F::zero());

//             assert_ne!(
//                 current_copy_perm_product,
//                 current_identity_perm_product
//             );

//             let z_eval = z_poly.evaluate(&current_root);
//             assert_ne!(z_eval, F::zero());

//             let z_eval_shifted = z_poly.evaluate(&next_root);
//             assert_ne!(z_eval_shifted, F::zero());

//             // Z(Xw) * copy_perm
//             let lhs = z_eval_shifted * current_copy_perm_product;
//             // Z(X) * iden_perm
//             let rhs = z_eval * current_identity_perm_product;
//             assert_eq!(
//                 lhs, rhs,
//                 "check failed at index: {}\'n lhs is : {:?} \n rhs is :{:?}",
//                 i, lhs, rhs
//             );
//         }

//         // Test that the shifted polynomial is correct
//         let shifted_z = shift_poly_by_one(fast_z_vec);
//         let shifted_z_poly = DensePolynomial::<F>::from_coefficients_vec(
//             domain.ifft(&shifted_z),
//         );
//         for element in domain.elements() {
//             let z_eval = z_poly.evaluate(&(element * domain.group_gen()));
//             let shifted_z_eval = shifted_z_poly.evaluate(&element);

//             assert_eq!(z_eval, shifted_z_eval)
//         }
//     }

//     // Test on Bls12-381
//     batch_test_field!(
//         [test_permutation_compute_sigmas_only_left_wires,
//         test_permutation_compute_sigmas,
//         test_basic_slow_permutation_poly
//         ],
//         []
//         => (
//             Bls12_381
//         )
//     );

//     // Test on Bls12-377
//     batch_test_field!(
//         [test_permutation_compute_sigmas_only_left_wires,
//         test_permutation_compute_sigmas,
//         test_basic_slow_permutation_poly
//         ],
//         []
//         => (
//             Bls12_377
//         )
//     );

//     // Test on Bls12-381
//     batch_test_field_params!(
//         [test_multizip_permutation_poly
//         ],
//         []
//         => (
//             Bls12_381,
//             ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Test on Bls12-377
//     batch_test_field_params!(
//         [test_multizip_permutation_poly
//         ],
//         []
//         => (
//             Bls12_377,
//             ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
