// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::{Field, FftField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};
use ark_serialize::{
    Read, Write,
    CanonicalDeserialize, CanonicalSerialize, SerializationError,
};

use crate::{
    error::Error,
    proof_system::ProverKey,
    util::{EvaluationDomainExt, compute_first_lagrange_evaluation},
};

use super::ExtendedProverKey;

/// Subset of the [`ProofEvaluations`]. Evaluations at `z` of the
/// wire polynomials
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WireEvaluations<F: Field> {
    /// Evaluation of the witness polynomial for the left wire at `z`.
    pub a: F,

    /// Evaluation of the witness polynomial for the right wire at `z`.
    pub b: F,

    /// Evaluation of the witness polynomial for the output wire at `z`.
    pub c: F,
}

/// Subset of the [`ProofEvaluations`]. Evaluations of the sigma and permutation
/// polynomials at `z`  or `z *w` where `w` is the nth root of unity.
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PermutationEvaluations<F: Field> {
    /// Evaluation of the left sigma polynomial at `z`.
    pub sigma1: F,

    /// Evaluation of the right sigma polynomial at `z`.
    pub sigma2: F,

    /// Evaluation of the permutation polynomial at `z * omega` where `omega`
    /// is a root of unity.
    pub z1_next: F,
}

// Probably all of these should go into CustomEvals
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, PartialEq)]
pub struct LookupEvaluations<F: Field> {
    /// Evaluations of the query polynomial at `z`
    pub f: F,

    // (Shifted) Evaluation of the lookup permutation polynomial at `z * root
    // of unity`
    pub z2_next: F,

    /// (Shifted) Evaluation of the even indexed half of sorted plonkup poly
    /// at `z root of unity
    pub h1_next: F,

    /// Evaluations of the odd indexed half of sorted plonkup poly at `z
    /// root of unity
    pub h2: F,

    pub t4: F,

    /// Evaluations of the table polynomial at `z`
    pub t: F,

    /// (Shifted) Evaluation of the table polynomial at `z * root of unity`
    pub t_next: F,
}

/// Set of evaluations that form the [`Proof`](super::Proof).
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProofEvaluations<F: Field> {
    /// Wire evaluations
    pub wire_evals: WireEvaluations<F>,

    /// Permutation and sigma polynomials evaluations
    pub perm_evals: PermutationEvaluations<F>,

    /// Lookup evaluations
    pub lookup_evals: LookupEvaluations<F>,
}

/// Compute the linearisation polynomial.
pub(crate) fn compute<'a, F, D, I>(
    domain: &D,
    pk: &ProverKey<F>,
    epk: &ExtendedProverKey<F>,
    pub_inputs: I,
    alpha: F,
    beta: F,
    gamma: F,
    delta: F,
    epsilon: F,
    zeta: F,
    z: F,
    a_poly: &DensePolynomial<F>,
    b_poly: &DensePolynomial<F>,
    c_poly: &DensePolynomial<F>,
    q_lo_poly: &DensePolynomial<F>,
    q_mid_poly: &DensePolynomial<F>,
    q_hi_poly: &DensePolynomial<F>,
    z1_poly: &DensePolynomial<F>,
    z2_poly: &DensePolynomial<F>,
    f_poly: &DensePolynomial<F>,
    h1_poly: &DensePolynomial<F>,
    h2_poly: &DensePolynomial<F>,
    t_poly: &DensePolynomial<F>,
) -> Result<(DensePolynomial<F>, ProofEvaluations<F>), Error>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    I: IntoIterator<Item = &'a F>,
{
    let n = domain.size();
    let shifted_z = z * domain.group_gen();

    // Wire evaluations
    let wire_evals = WireEvaluations {
        a: a_poly.evaluate(&z),
        b: b_poly.evaluate(&z),
        c: c_poly.evaluate(&z),
    };

    // Permutation evaluations
    let perm_evals = PermutationEvaluations {
        sigma1: pk.perm.sigma1.evaluate(&z),
        sigma2: pk.perm.sigma2.evaluate(&z),
        z1_next: z1_poly.evaluate(&shifted_z),
    };

    // Compute the last term in the linearisation polynomial
    // (negative_quotient_term):
    // - Z_h(z_challenge) * [t_1(X) + z_challenge^n * t_2(X) + z_challenge^2n *
    //   t_3(X) + z_challenge^3n * t_4(X)]
    let vanishing_poly_eval = domain.evaluate_vanishing_polynomial(z);
    let l_1_eval = compute_first_lagrange_evaluation(
        n,
        vanishing_poly_eval,
        z,
    );

    let lookup_evals = LookupEvaluations {
        f: f_poly.evaluate(&z),
        z2_next: z2_poly.evaluate(&shifted_z),
        h1_next: h1_poly.evaluate(&shifted_z),
        h2: h2_poly.evaluate(&z),
        t4: epk.lookup.t4.evaluate(&z),
        t: t_poly.evaluate(&z),
        t_next: t_poly.evaluate(&shifted_z),
    };

    let arith_constraint = pk.arith.compute_linearisation(
        &wire_evals,
        pub_inputs,
        &epk.arith.lagranges,
    );

    let permutation = pk.perm.compute_linearisation(
        alpha,
        beta,
        gamma,
        z,
        l_1_eval,
        &wire_evals,
        &perm_evals,
        z1_poly,
    )?;

    let lookup = pk.lookup.compute_linearisation(
        alpha,
        delta,
        epsilon,
        zeta,
        l_1_eval,
        &wire_evals,
        &lookup_evals,
        z2_poly,
        h1_poly,
    );

    let z_exp_n_plus_2 = (vanishing_poly_eval + F::one()) * z.square();
    let quotient_term = &(&(&(&(q_hi_poly * z_exp_n_plus_2)
        + q_mid_poly)
        * z_exp_n_plus_2)
        + q_lo_poly)
        * vanishing_poly_eval;
    let negative_quotient_term = &quotient_term * (-F::one());

    let linearisation_polynomial = arith_constraint
        + permutation
        + lookup
        + negative_quotient_term;

    Ok((
        linearisation_polynomial,
        ProofEvaluations {
            wire_evals,
            perm_evals,
            lookup_evals,
        },
    ))
}
