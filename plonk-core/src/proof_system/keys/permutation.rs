// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK Permutation Prover and Verifier Data

use crate::{
    error::Error,
    permutation::constants::{K1, K2},
    proof_system::linearisation_poly::{
        ProofEvaluations,
        WireEvaluations,
        PermutationEvaluations,
    },
};
use ark_ff::{FftField, Field};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::PCCommitment;
use ark_serialize::*;

/// Permutation Prover Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Eq(bound = ""),
    PartialEq(bound = "")
)]
pub struct ProverKey<F: Field> {
    /// Left Permutation
    pub sigma1: DensePolynomial<F>,

    /// Right Permutation
    pub sigma2: DensePolynomial<F>,

    /// Output Permutation
    pub sigma3: DensePolynomial<F>,
}

impl<F: Field> ProverKey<F> {
    /// Computes the permutation term of the linearisation polynomial.
    pub(crate) fn compute_linearisation(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        z: F,
        l_1_eval: F,
        wire_evals: &WireEvaluations<F>,
        perm_evals: &PermutationEvaluations<F>,
        z1_poly: &DensePolynomial<F>,
    ) -> Result<DensePolynomial<F>, Error> {
        // Computes the following:
        // (a_eval + beta * z + gamma) * (b_eval + beta * K1 * z +
        // gamma) * (c_eval + beta * K2 * z + gamma) * alpha * z1(X)
        let part_1 = {
            let beta_mul_z = beta * z;
            z1_poly * (
                alpha
                * (beta_mul_z + wire_evals.a + gamma)
                * (K1::<F>() * beta_mul_z + wire_evals.b + gamma)
                * (K2::<F>() * beta_mul_z + wire_evals.c + gamma)
            )
        };

        // Computes the following:
        // -(a_eval + beta * sigma1 + gamma)(b_eval + beta * sigma2 + gamma)
        // * beta * z1_next_eval * alpha * sigma3(X)
        let part_2 =
            &self.sigma3 * (
                -alpha
                * beta
                * perm_evals.z1_next
                * (beta * perm_evals.sigma1 + wire_evals.a + gamma)
                * (beta * perm_evals.sigma2 + wire_evals.b + gamma)
            );

        // Computes the lineariser check.
        let part_3 = z1_poly * (l_1_eval * alpha.square());

        Ok(&(&part_1 + &part_2) + &part_3)
    }
}

/// Permutation Prover Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = ""),
    Eq(bound = ""),
    PartialEq(bound = "")
)]
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
        // (a(x) + beta * X + gamma) * (b(X) + beta * k1 * X + gamma) * (c(X) + beta *
        // k2 * X + gamma) * z(X) * alpha
        let part_1 = {
            let x = self.x_coset[i];
            alpha
            * z1_i
            * (a_i + (beta * x) + gamma)
            * (b_i + (beta * K1::<F>() * x) + gamma)
            * (c_i + (beta * K1::<F>() * x) + gamma)
        };

        // Computes the following:
        // - (a(x) + beta * Sigma1(X) + gamma) * (b(X) + beta * Sigma2(X) + gamma) * (c(X)
        // + beta * Sigma3(X) + gamma) * z(X*omega) * alpha
        let part_2 = {
            let sigma1_eval = self.sigma1_coset[i];
            let sigma2_eval = self.sigma2_coset[i];
            let sigma3_eval = self.sigma3_coset[i];
            -alpha
            * z1_i_next
            * (a_i + (beta * sigma1_eval) + gamma)
            * (b_i + (beta * sigma2_eval) + gamma)
            * (c_i + (beta * sigma3_eval) + gamma)
        };

        // Computes the following:
        // L_1(X) * [Z(X) - 1] * alpha^2
        let part_3 = (z1_i - F::one()) * l_1_i * alpha.square();

        part_1 + part_2 + part_3
    }
}

/// Permutation Verifier Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = "PCC: core::fmt::Debug"),
    Eq(bound = "PCC: Eq"),
    PartialEq(bound = "PCC: PartialEq")
)]
pub struct VerifierKey<PCC>
where
    PCC: PCCommitment + Default,
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
    PCC: PCCommitment + Default,
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
        z: F,
        l_1_eval: F,
        z1_comm: PCC,
    ) {
        // (a_eval + beta * z + gamma)(b_eval + beta * z * k1 +
        // gamma)(c_eval + beta * k2 * z + gamma) * alpha + l_1_eval * alpha^2
        let beta_mul_z = beta * z;
        let scalar = alpha
            * (beta_mul_z + evaluations.wire_evals.a + gamma)
            * (beta_mul_z * K1::<F>() + evaluations.wire_evals.b + gamma)
            * (beta_mul_z * K1::<F>() + evaluations.wire_evals.c + gamma)
            + (l_1_eval * alpha.square());
        scalars.push(scalar);
        points.push(z1_comm);

        // -(a(z) + β * σ1(z) + γ) * (b(z) + β * σ2(z) + γ) * z1(ωz) * α * β
        let scalar = -alpha
            * beta
            * evaluations.perm_evals.z1_next
            * (beta * evaluations.perm_evals.sigma1 + evaluations.wire_evals.a + gamma)
            * (beta * evaluations.perm_evals.sigma2 + evaluations.wire_evals.b + gamma);
        scalars.push(scalar);
        points.push(self.sigma3.clone());
    }
}
