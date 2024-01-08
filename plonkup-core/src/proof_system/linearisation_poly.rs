// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, Polynomial};

use crate::{
    proof_system::{
        ProverKey, ProofEvaluations, WireEvaluations,
        PermutationEvaluations, LookupEvaluations,
    },
    util::{EvaluationDomainExt, compute_lagrange_evaluation},
};

/// Compute the linearisation polynomial.
pub(crate) fn compute<F, D>(
    domain: &D,
    pk: &ProverKey<F>,
    alpha: F,
    beta: F,
    gamma: F,
    delta: F,
    epsilon: F,
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
) -> (DensePolynomial<F>, ProofEvaluations<F>)
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
{
    let shifted_z = z * domain.group_gen();

    let zh_eval = domain.evaluate_vanishing_polynomial(z);
    let l_1_eval = compute_lagrange_evaluation(
        domain.size(),
        F::one(),
        zh_eval,
        z,
    );

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

    let lookup_evals = LookupEvaluations {
        f: f_poly.evaluate(&z),
        z2_next: z2_poly.evaluate(&shifted_z),
        h1_next: h1_poly.evaluate(&shifted_z),
        h2: h2_poly.evaluate(&z),
        t: t_poly.evaluate(&z),
        t_next: t_poly.evaluate(&shifted_z),
    };

    let arith = pk.arith.compute_linearisation(&wire_evals);

    let permutation = pk.perm.compute_linearisation(
        alpha,
        beta,
        gamma,
        z,
        l_1_eval,
        &wire_evals,
        &perm_evals,
        z1_poly,
    );

    let lookup = pk.lookup.compute_linearisation(
        alpha,
        delta,
        epsilon,
        l_1_eval,
        &wire_evals,
        &lookup_evals,
        z2_poly,
        h1_poly,
    );

    // Compute the last term in the linearisation polynomial
    // (negative_quotient_term):
    // - zh(z) * [q_low(x) + z^(n+2)*q_mid(x) + z^(2n+4)*q_high(x)]
    let z_exp_n_plus_2 = (zh_eval + F::one()) * z.square();
    let quotient_term = &(&(&(&(q_hi_poly * z_exp_n_plus_2)
        + q_mid_poly)
        * z_exp_n_plus_2)
        + q_lo_poly)
        * -zh_eval;

    let linearisation_polynomial = arith + permutation + lookup + quotient_term;

    (
        linearisation_polynomial,
        ProofEvaluations {
            wire_evals,
            perm_evals,
            lookup_evals,
        },
    )
}
