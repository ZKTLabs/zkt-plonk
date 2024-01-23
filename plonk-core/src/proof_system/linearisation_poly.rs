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
    xi: F,
    a_poly: &DensePolynomial<F>,
    b_poly: &DensePolynomial<F>,
    c_poly: &DensePolynomial<F>,
    q_lo_poly: &DensePolynomial<F>,
    q_mid_poly: &DensePolynomial<F>,
    q_hi_poly: &DensePolynomial<F>,
    z1_poly: &DensePolynomial<F>,
    z2_poly: &DensePolynomial<F>,
    h1_poly: &DensePolynomial<F>,
    h2_poly: &DensePolynomial<F>,
    t_poly: &DensePolynomial<F>,
) -> (DensePolynomial<F>, ProofEvaluations<F>)
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
{
    let shifted_xi = xi * domain.group_gen();

    let zh_eval = domain.evaluate_vanishing_polynomial(xi);
    let l_1_eval = compute_lagrange_evaluation(
        domain.size(),
        F::one(),
        zh_eval,
        xi,
    );

    // Wire evaluations
    let wire_evals = WireEvaluations {
        a: a_poly.evaluate(&xi),
        b: b_poly.evaluate(&xi),
        c: c_poly.evaluate(&xi),
    };

    // Permutation evaluations
    let perm_evals = PermutationEvaluations {
        sigma1: pk.perm.sigma1.evaluate(&xi),
        sigma2: pk.perm.sigma2.evaluate(&xi),
        z1_next: z1_poly.evaluate(&shifted_xi),
    };

    let lookup_evals = LookupEvaluations {
        q_lookup: pk.lookup.q_lookup.evaluate(&xi),
        t: t_poly.evaluate(&xi),
        t_next: t_poly.evaluate(&shifted_xi),
        z2_next: z2_poly.evaluate(&shifted_xi),
        h1_next: h1_poly.evaluate(&shifted_xi),
        h2: h2_poly.evaluate(&xi),
    };

    let arith = pk.arith.compute_linearisation(&wire_evals);

    let permutation = pk.perm.compute_linearisation(
        alpha,
        beta,
        gamma,
        xi,
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
    // - zh(ξ) * [q_low(x) + ξ^(n+2)*q_mid(x) + ξ^(2n+4)*q_high(x)]
    let xi_exp_n_plus_2 = (zh_eval + F::one()) * xi.square();
    let quotient_term = &(&(&(&(q_hi_poly * xi_exp_n_plus_2)
        + q_mid_poly)
        * xi_exp_n_plus_2)
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
