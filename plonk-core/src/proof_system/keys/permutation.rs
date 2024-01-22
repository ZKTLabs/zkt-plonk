// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK Permutation Prover and Verifier Data

use ark_ff::{FftField, Field};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::{PCCommitment, LabeledPolynomial};
use ark_serialize::*;

use crate::{
    permutation::constants::{K1, K2},
    proof_system::{ProofEvaluations, WireEvaluations, PermutationEvaluations},
};

/// Permutation Prover Key
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ProverKey<F: Field> {
    /// Left Permutation
    pub sigma1: LabeledPolynomial<F, DensePolynomial<F>>,

    /// Right Permutation
    pub sigma2: LabeledPolynomial<F, DensePolynomial<F>>,

    /// Output Permutation
    pub sigma3: LabeledPolynomial<F, DensePolynomial<F>>,
}

impl<F: Field> ProverKey<F> {
    /// Computes the permutation term of the linearisation polynomial.
    pub(crate) fn compute_linearisation(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        xi: F,
        l_1_eval: F,
        wire_evals: &WireEvaluations<F>,
        perm_evals: &PermutationEvaluations<F>,
        z1_poly: &DensePolynomial<F>,
    ) -> DensePolynomial<F> {
        // Computes the following:
        // ((a(ξ) + β*ξ + γ) * (b(ξ) + β*K1*ξ + γ) * (c(ξ) + β*K2*ξ + γ) * α + L_1(ξ) * α^2) * z1(x)
        let part_1 = {
            let beta_mul_xi = beta * xi;
            z1_poly * (
                alpha
                    * (beta_mul_xi + wire_evals.a + gamma)
                    * (beta_mul_xi * K1::<F>() + wire_evals.b + gamma)
                    * (beta_mul_xi * K2::<F>() + wire_evals.c + gamma)
                    + (l_1_eval * alpha.square())
            )
        };

        // Computes the following:
        // -(a(ξ) + β*σ1(ξ) + γ) * (b(ξ) + β*σ2(ξ) + γ) * β * z1(ωξ) * α * σ3(x)
        let part_2 =
            self.sigma3.polynomial() * (
                -alpha
                    * beta
                    * perm_evals.z1_next
                    * (beta * perm_evals.sigma1 + wire_evals.a + gamma)
                    * (beta * perm_evals.sigma2 + wire_evals.b + gamma)
            );

        part_1 + part_2
    }
}

/// Permutation Prover Key
#[derive(Debug, Clone, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ExtendedProverKey<F: FftField> {
    /// Left Permutation
    pub sigma1: Vec<F>,
    /// 
    pub sigma1_coset: Vec<F>,

    /// Right Permutation
    pub sigma2: Vec<F>,
    /// 
    pub sigma2_coset: Vec<F>,

    /// Output Permutation
    pub sigma3: Vec<F>,
    /// 
    pub sigma3_coset: Vec<F>,

    ///
    pub x_coset: Vec<F>,
}

impl<F: FftField> ExtendedProverKey<F> {
    /// Computes permutation term of the quotient polynomial at the `i`th domain
    /// point.
    pub(crate) fn compute_quotient_i(
        &self,
        i: usize,
        alpha: F,
        beta: F,
        gamma: F,
        a_i: F,
        b_i: F,
        c_i: F,
        z1_i: F,
        z1_i_next: F,
        l_1_i: F,
    ) -> F {
        // Computes the following:
        // (a(x) + β*x + γ) * (b(x) + β*k1*x + γ) * (c(x) + β*k2*x + γ) * z1(x) * α
        let part_1 = {
            let beta_mul_x = beta * self.x_coset[i];
            alpha
                * z1_i
                * (beta_mul_x + a_i + gamma)
                * (beta_mul_x * K1::<F>() + b_i + gamma)
                * (beta_mul_x * K2::<F>() + c_i + gamma)
        };

        // Computes the following:
        // - (a(x) + β*σ1(x) + γ) * (b(x) + β*σ2(x) + γ) * (c(x) + β*σ3(x) + γ) * z1(xω) * α
        let part_2 = {
            let sigma1_eval = self.sigma1_coset[i];
            let sigma2_eval = self.sigma2_coset[i];
            let sigma3_eval = self.sigma3_coset[i];
            -alpha
                * z1_i_next
                * (beta * sigma1_eval + a_i + gamma)
                * (beta * sigma2_eval + b_i + gamma)
                * (beta * sigma3_eval + c_i + gamma)
        };

        // Computes the following:
        // L_1(x) * [z1(x) - 1] * α^2
        let part_3 = (z1_i - F::one()) * l_1_i * alpha.square();

        part_1 + part_2 + part_3
    }
}

/// Permutation Verifier Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = "PCC: Clone"),
    Debug(bound = "PCC: core::fmt::Debug"),
    Eq(bound = "PCC: Eq"),
    PartialEq(bound = "PCC: PartialEq")
)]
pub struct VerifierKey<PCC>
where
    PCC: PCCommitment,
{
    /// Left Permutation Commitment
    pub sigma1: PCC,

    /// Right Permutation Commitment
    pub sigma2: PCC,

    /// Output Permutation Commitment
    pub sigma3: PCC,
}

impl<PCC> VerifierKey<PCC>
where
    PCC: PCCommitment,
{
    /// Computes the linearisation commitments.
    pub(crate) fn compute_linearisation_commitment<F: Field>(
        &self,
        scalars: &mut Vec<F>,
        points: &mut Vec<PCC>,
        evaluations: &ProofEvaluations<F>,
        alpha: F,
        beta: F,
        gamma: F,
        xi: F,
        l_1_eval: F,
        z1_comm: PCC,
    ) {
        // (a(ξ) + β*ξ + γ) * (b(ξ) + β*K1*ξ + γ) * (c(ξ) + β*K2*ξ + γ) * α + L_1(ξ) * α^2
        let beta_mul_z = beta * xi;
        let scalar = alpha
            * (beta_mul_z + evaluations.wire_evals.a + gamma)
            * (beta_mul_z * K1::<F>() + evaluations.wire_evals.b + gamma)
            * (beta_mul_z * K2::<F>() + evaluations.wire_evals.c + gamma)
            + (l_1_eval * alpha.square());
        scalars.push(scalar);
        points.push(z1_comm);

        // -(a(ξ) + β*σ1(ξ) + γ) * (b(ξ) + β*σ2(ξ) + γ) * z1(ωξ) * α * β
        let scalar = -alpha
            * beta
            * evaluations.perm_evals.z1_next
            * (beta * evaluations.perm_evals.sigma1 + evaluations.wire_evals.a + gamma)
            * (beta * evaluations.perm_evals.sigma2 + evaluations.wire_evals.b + gamma);
        scalars.push(scalar);
        points.push(self.sigma3.clone());
    }
}
