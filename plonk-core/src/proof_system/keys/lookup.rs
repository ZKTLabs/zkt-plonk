// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.
//! Lookup gates

use ark_ff::{FftField, Field};
use ark_poly::polynomial::univariate::DensePolynomial;
use ark_poly_commit::LabeledPolynomial;
use ark_serialize::*;

use crate::{
    proof_system::{ProofEvaluations, WireEvaluations, LookupEvaluations},
    commitment::HomomorphicCommitment,
};

/// Lookup Gates Prover Key
#[derive(Debug, Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct ProverKey<F: Field> {
    /// Lookup selector
    pub q_lookup: LabeledPolynomial<F, DensePolynomial<F>>,
    /// Table selector
    pub q_table: LabeledPolynomial<F, DensePolynomial<F>>,
}

impl<F: Field> ProverKey<F> {
    /// Compute linearization for lookup gates
    pub(crate) fn compute_linearization(
        &self,
        alpha: F,
        delta: F,
        epsilon: F,
        l_1_eval: F,
        wire_evals: &WireEvaluations<F>,
        lookup_evals: &LookupEvaluations<F>,
        z2_poly: &DensePolynomial<F>,
        h1_poly: &DensePolynomial<F>,
    ) -> DensePolynomial<F> {
        let alpha_cu = alpha.square() * alpha;
        let alpha_qu = alpha_cu * alpha;
        let one_plus_delta = delta + F::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // [α^3 * (1+δ) * (ε + q_lookup(ξ)*c(ξ)) * (ε(1+δ) + t(ξ) + δ*t(ωξ)) + α^4 * L_1(ξ)] * z2(x)
        let part_1 = z2_poly * (
            alpha_cu
                * one_plus_delta
                * (epsilon + lookup_evals.q_lookup * wire_evals.c)
                * (epsilon_one_plus_delta + lookup_evals.t + delta * lookup_evals.t_next)
                + alpha_qu * l_1_eval
        );

        // -α^3 * z2(ωξ) * (ε(1+δ) + h2(ξ) + δ*h1(ωξ)) * h1(x)
        let part_2 = h1_poly * (
            -alpha_cu * lookup_evals.z2_next
                * (epsilon_one_plus_delta + lookup_evals.h2 + delta * lookup_evals.h1_next)
        );

        // q_table(x) * t(ξ) * α^5
        let part_3 =
            self.q_table.polynomial() * (alpha_qu * alpha * lookup_evals.t);

        part_1 + part_2 + part_3
    }
}

/// Lookup Gates Extended Prover Key
#[derive(Debug, Clone, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ExtendedProverKey<F: FftField> {
    /// Lookup selector
    pub q_lookup: Vec<F>,
    ///
    pub q_lookup_coset: Vec<F>,
    ///
    pub q_table_coset: Vec<F>,
}

impl<F: FftField> ExtendedProverKey<F> {
    /// Compute evals of lookup portion of quotient polynomial
    pub(crate) fn compute_quotient_i(
        &self,
        i: usize,
        alpha: F,
        delta: F,
        epsilon: F,
        c_i: F,
        t_i: F,
        t_i_next: F,
        h1_i: F,
        h1_i_next: F,
        h2_i: F,
        z2_i: F,
        z2_i_next: F,
        l_1_i: F,
    ) -> F {
        let alpha_cu = alpha.square() * alpha;
        let alpha_qu = alpha_cu * alpha;
        let one_plus_delta = delta + F::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // α^3 * z2(x) * (1+δ) * (ε + q_lookup(x)*c(x)) * (ε*(1+δ) + t(x) + δt(xω))
        let part_1 = alpha_cu
            * z2_i
            * one_plus_delta
            * (epsilon + self.q_lookup_coset[i] * c_i)
            * (epsilon_one_plus_delta + t_i + delta * t_i_next);

        // − α^3 * z2(xω) * (ε*(1+δ) + h1(x) + δ*h2(x)) * (ε*(1+δ) + h2(x) + δ*h1(xω))
        let part_2 = -alpha_cu
            * z2_i_next
            * (epsilon_one_plus_delta + h1_i + delta * h2_i)
            * (epsilon_one_plus_delta + h2_i + delta * h1_i_next);

        // α^4 * (z2(x) - 1) * L_1(x)
        let part_3 = alpha_qu * (z2_i - F::one()) * l_1_i;

        // α^5 * q_table(x) * t(x)
        let part_4 = alpha_qu * alpha * self.q_table_coset[i] * t_i;

        part_1 + part_2 + part_3 + part_4
    }
}

/// LookUp Verifier Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = "PC::Commitment: Clone"),
    Debug(bound = "PC::Commitment: core::fmt::Debug"),
    Eq(bound = "PC::Commitment: Eq"),
    PartialEq(bound = "PC::Commitment: PartialEq")
)]
pub struct VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Lookup Selector Commitment
    pub q_lookup: PC::Commitment,
    /// Table Selector Commitment
    pub q_table: PC::Commitment,
}

impl<F, PC> VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Computes the linearization commitments.
    pub(crate) fn compute_linearization_commitment(
        &self,
        scalars: &mut Vec<F>,
        points: &mut Vec<PC::Commitment>,
        evaluations: &ProofEvaluations<F>,
        alpha: F,
        delta: F,
        epsilon: F,
        l_1_eval: F,
        z2_comm: PC::Commitment,
        h1_comm: PC::Commitment,
    ) {
        let alpha_cu = alpha.square() * alpha;
        let alpha_qu = alpha_cu * alpha;
        let one_plus_delta = F::one() + delta;
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // α^3 * (1+δ) * (ε + q_lookup(ξ)*c(ξ)) * (ε(1+δ) + t(ξ) + δ*t(ωξ)) + α^4 * L_1(ξ)
        let scalar = alpha_cu
            * one_plus_delta
            * (epsilon + evaluations.lookup_evals.q_lookup * evaluations.wire_evals.c)
            * (epsilon_one_plus_delta + evaluations.lookup_evals.t + delta * evaluations.lookup_evals.t_next)
            + alpha_qu * l_1_eval;
        scalars.push(scalar);
        points.push(z2_comm);

        // -α^3 * z2(ωξ) * (ε(1+δ) + h2(ξ) + δ * h1(ωξ))
        let scalar = -alpha_cu * evaluations.lookup_evals.z2_next
            * (epsilon_one_plus_delta + evaluations.lookup_evals.h2 + delta * evaluations.lookup_evals.h1_next);
        scalars.push(scalar);
        points.push(h1_comm);

        // α^5 * t(ξ)
        let scalar = alpha_qu * alpha * evaluations.lookup_evals.t;
        scalars.push(scalar);
        points.push(self.q_table.clone());
    }
}
