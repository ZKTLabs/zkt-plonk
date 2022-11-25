// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Arithmetic Gates

use ark_ff::{FftField, Field};
use ark_poly::{polynomial::univariate::DensePolynomial};
use ark_serialize::*;

use crate::proof_system::linearisation_poly::{ProofEvaluations, WireEvaluations};
use crate::commitment::HomomorphicCommitment;

/// Arithmetic Gates Prover Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Eq, PartialEq)]
pub struct ProverKey<F: Field> {
    /// Multiplication Selector
    pub q_m: DensePolynomial<F>,
    /// Left Wire Selector
    pub q_l: DensePolynomial<F>,
    /// Right Wire Selector
    pub q_r: DensePolynomial<F>,
    /// Output Wire Selector
    pub q_o: DensePolynomial<F>,
    /// Constant Selector
    pub q_c: DensePolynomial<F>,
}

impl<F: Field> ProverKey<F> {
    /// Computes the arithmetic gate contribution to the linearisation
    /// polynomial at the given evaluation points.
    pub(crate) fn compute_linearisation<'a, I>(
        &self,
        wire_evals: &WireEvaluations<F>,
        pub_inputs: I,
        lagranges: &[DensePolynomial<F>],
    ) -> DensePolynomial<F>
    where
        I: IntoIterator<Item = &'a F>,
    {
        let poly = &(&self.q_m * (wire_evals.a * wire_evals.b)
            + (&self.q_l * wire_evals.a)
            + (&self.q_r * wire_evals.b)
            + (&self.q_o * wire_evals.c))
            + &self.q_c;

        pub_inputs
            .into_iter()
            .zip(lagranges)
            .fold(poly, |acc, (&pi, l_poly)| {
                &acc + &(l_poly * pi)
            })
    }
}

/// Arithmetic Gates Extended Prover Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Eq, PartialEq)]
pub struct ExtendedProverKey<F: FftField> {
    /// Multiplication Selector
    pub q_m_coset: Vec<F>,
    /// Left Wire Selector
    pub q_l_coset: Vec<F>,
    /// Right Wire Selector
    pub q_r_coset: Vec<F>,
    /// Output Wire Selector
    pub q_o_coset: Vec<F>,
    /// Constant Selector
    pub q_c_coset: Vec<F>,
    ///
    pub lagranges: Vec<DensePolynomial<F>>,
}

impl<F: FftField> ExtendedProverKey<F> {
    /// Computes the arithmetic gate contribution to the quotient polynomial at
    /// the element of the domain at the given `index`.
    pub(crate) fn compute_quotient_i(
        &self,
        i: usize,
        a_i: F,
        b_i: F,
        c_i: F,
        pi_i: F,
    ) -> F {
        (a_i * b_i * self.q_m_coset[i])
            + (a_i * self.q_l_coset[i])
            + (b_i * self.q_r_coset[i])
            + (c_i * self.q_o_coset[i])
            + self.q_c_coset[i]
            + pi_i
    }
}

/// Arithmetic Gates Verifier Key
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone,
    Debug(bound = "PC::Commitment: std::fmt::Debug"),
    Eq(bound = "PC::Commitment: Eq"),
    PartialEq(bound = "PC::Commitment: PartialEq")
)]
pub struct VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Multiplication Selector Commitment
    pub q_m: PC::Commitment,
    /// Left Selector Commitment
    pub q_l: PC::Commitment,
    /// Right Selector Commitment
    pub q_r: PC::Commitment,
    /// Output Selector Commitment
    pub q_o: PC::Commitment,
    /// Constant Selector Commitment
    pub q_c: PC::Commitment,
    /// Lagrange poly commitments for public inputs
    pub lagranges: Vec<PC::Commitment>,
}

impl<F, PC> VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Computes arithmetic gate contribution to the linearisation polynomial
    /// commitment.
    pub(crate) fn compute_linearisation_commitment(
        &self,
        scalars: &mut Vec<F>,
        points: &mut Vec<PC::Commitment>,
        evaluations: &ProofEvaluations<F>,
        pub_inputs: &[F],
    ) {
        scalars.push(evaluations.wire_evals.a * evaluations.wire_evals.b);
        points.push(self.q_m.clone());

        scalars.push(evaluations.wire_evals.a);
        points.push(self.q_l.clone());

        scalars.push(evaluations.wire_evals.b);
        points.push(self.q_r.clone());

        scalars.push(evaluations.wire_evals.c);
        points.push(self.q_o.clone());

        scalars.push(F::one());
        points.push(self.q_c.clone());

        scalars.extend_from_slice(pub_inputs);
        points.extend_from_slice(&self.lagranges);
    }
}
