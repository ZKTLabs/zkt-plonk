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
    pub(crate) fn compute_linearisation(
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
        let alpha_sq = alpha.square();
        let alpha_qu = alpha_sq.square();
        let one_plus_delta = delta + F::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // q_lookup(x) * (c(z) - f(z)) * α^3
        let part_1 =
            self.q_lookup.polynomial() * (alpha_sq * alpha * (wire_evals.c - lookup_evals.f));

        // z2(x) * [(1+δ) * (ε+f(z)) * (ε(1+δ) + t(z) + δ*t(ωz)) * α^4 + L_1(z) * α^5]
        let part_2 = z2_poly * (
            alpha_qu
                * one_plus_delta
                * (epsilon + lookup_evals.f)
                * (delta * lookup_evals.t_next + epsilon_one_plus_delta + lookup_evals.t)
                + (l_1_eval * alpha_qu * alpha)
        );

        // h1(x) * -z2(ωz) * (ε(1+δ) + h2(z) + δ*h1(ωz)) * α^4
        let part_3 = h1_poly * (
            -alpha_qu
                * lookup_evals.z2_next
                * (delta * lookup_evals.h1_next + epsilon_one_plus_delta + lookup_evals.h2)
        );

        // q_table(x) * t(z) * α^5
        let part_4 =
            self.q_table.polynomial() * (alpha_qu * alpha_sq * lookup_evals.t);

        part_1 + part_2 + part_3 + part_4
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
        a_i: F,
        b_i: F,
        c_i: F,
        f_i: F,
        t_i: F,
        t_i_next: F,
        h1_i: F,
        h1_i_next: F,
        h2_i: F,
        z2_i: F,
        z2_i_next: F,
        l_1_i: F,
    ) -> F {
        let alpha_sq = alpha.square();
        let alpha_qu = alpha_sq.square();
        let one_plus_delta = delta + F::one();
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // q_lookup(x) * (c(x) - f(x)) * α^3
        let part_1 = alpha_sq * alpha * (c_i - f_i) * self.q_lookup_coset[i];

        // z2(x) * (1+δ) * (ε+f(x)) * (ε*(1+δ) + t(x) + δt(xω)) * α^4
        let part_2 = alpha_qu
            * one_plus_delta
            * (epsilon + f_i)
            * (delta * t_i_next + epsilon_one_plus_delta + t_i)
            * z2_i;

        // − z2(xω) * (ε*(1+δ) + h1(x) + δ*h2(x)) * (ε*(1+δ) + h2(x) + δ*h1(xω)) * α^4
        let part_3 = -alpha_qu
            * z2_i_next
            * (delta * h2_i + h1_i + epsilon_one_plus_delta)
            * (delta * h1_i_next + h2_i + epsilon_one_plus_delta);

        let part_4 = (z2_i - F::one()) * l_1_i * alpha_qu * alpha;

        // q_table(x) * t(x) * α^6
        let part_5 = self.q_table_coset[i] * t_i * alpha_qu * alpha_sq;

        part_1 + part_2 + part_3 + part_4 + part_5
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
    /// Computes the linearisation commitments.
    pub(crate) fn compute_linearisation_commitment(
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
        let alpha_sq = alpha.square();
        let alpha_qu = alpha_sq.square();
        let one_plus_delta = F::one() + delta;
        let epsilon_one_plus_delta = epsilon * one_plus_delta;

        // (c(z) - f(z)) * α^3
        let scalar =
            alpha_sq * alpha * (evaluations.wire_evals.c - evaluations.lookup_evals.f);
        scalars.push(scalar);
        points.push(self.q_lookup.clone());

        // (1+δ) * (ε+f(z)) * (ε(1+δ) + t(z) + δ*t(ωz)) * α^4 + L_1(z) * α^5
        let scalar = alpha_qu
            * one_plus_delta
            * (epsilon + evaluations.lookup_evals.f)
            * (delta * evaluations.lookup_evals.t_next
                + epsilon_one_plus_delta + evaluations.lookup_evals.t)
            + (l_1_eval * alpha_qu * alpha);
        scalars.push(scalar);
        points.push(z2_comm);

        // -(ε(1+δ) + h2(z) + δ * h1(ωz)) * z2(ωz) * α^4
        let scalar = -alpha_qu
            * evaluations.lookup_evals.z2_next
            * (delta * evaluations.lookup_evals.h1_next
                + epsilon_one_plus_delta + evaluations.lookup_evals.h2);
        scalars.push(scalar);
        points.push(h1_comm);

        // t(z) * α^6
        let scalar = alpha_qu * alpha_sq * evaluations.lookup_evals.t;
        scalars.push(scalar);
        points.push(self.q_table.clone());
    }
}
