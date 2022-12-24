// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    error::Error,
    util::{poly_from_coset_evals, coset_evals_from_poly_ref},
};
use super::ExtendedProverKey;

/// Computes the Quotient [`DensePolynomial`] given the [`EvaluationDomain`], a
/// [`ProverKey`], and some other info.
pub fn compute<F, D>(
    domain: &D,
    epk: &ExtendedProverKey<F>,
    alpha: F,
    beta: F,
    gamma: F,
    delta: F,
    epsilon: F,
    zeta: F,
    z1_poly: &DensePolynomial<F>,
    z2_poly: &DensePolynomial<F>,
    a_poly: &DensePolynomial<F>,
    b_poly: &DensePolynomial<F>,
    c_poly: &DensePolynomial<F>,
    pi_poly: &DensePolynomial<F>,
    f_poly: &DensePolynomial<F>,
    h1_poly: &DensePolynomial<F>,
    h2_poly: &DensePolynomial<F>,
    t_poly: &DensePolynomial<F>,
) -> Result<DensePolynomial<F>, Error>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    let n = domain.size();
    // Size of quotient poly is 3n+5
    assert!(n >= 5);

    let domain_4n = D::new(4 * n)
        .ok_or(Error::InvalidEvalDomainSize {
            log_size_of_group: (4 * n).trailing_zeros(),
            adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
        })?;

    let mut z1_coset = coset_evals_from_poly_ref(&domain_4n, z1_poly);
    z1_coset.push(z1_coset[0]);
    z1_coset.push(z1_coset[1]);
    z1_coset.push(z1_coset[2]);
    z1_coset.push(z1_coset[3]);

    let mut z2_coset = coset_evals_from_poly_ref(&domain_4n, z2_poly);
    z2_coset.push(z2_coset[0]);
    z2_coset.push(z2_coset[1]);
    z2_coset.push(z2_coset[2]);
    z2_coset.push(z2_coset[3]);

    let mut a_coset = coset_evals_from_poly_ref(&domain_4n, a_poly);
    a_coset.push(a_coset[0]);
    a_coset.push(a_coset[1]);
    a_coset.push(a_coset[2]);
    a_coset.push(a_coset[3]);

    let mut b_coset = coset_evals_from_poly_ref(&domain_4n, b_poly);
    b_coset.push(b_coset[0]);
    b_coset.push(b_coset[1]);
    b_coset.push(b_coset[2]);
    b_coset.push(b_coset[3]);

    let mut c_coset = coset_evals_from_poly_ref(&domain_4n, c_poly);
    c_coset.push(c_coset[0]);
    c_coset.push(c_coset[1]);
    c_coset.push(c_coset[2]);
    c_coset.push(c_coset[3]);

    let pi_coset = coset_evals_from_poly_ref(&domain_4n, pi_poly);

    let f_coset = coset_evals_from_poly_ref(&domain_4n, f_poly);

    let mut t_coset = coset_evals_from_poly_ref(&domain_4n, t_poly);
    t_coset.push(t_coset[0]);
    t_coset.push(t_coset[1]);
    t_coset.push(t_coset[2]);
    t_coset.push(t_coset[3]);

    let mut h1_coset = coset_evals_from_poly_ref(&domain_4n, h1_poly);
    h1_coset.push(h1_coset[0]);
    h1_coset.push(h1_coset[1]);
    h1_coset.push(h1_coset[2]);
    h1_coset.push(h1_coset[3]);

    let h2_coset = coset_evals_from_poly_ref(&domain_4n, h2_poly);

    #[cfg(not(feature = "parallel"))]
    let arith = itertools::izip!(
        a_coset.iter(),
        b_coset.iter(),
        c_coset.iter(),
        pi_coset,
    );
    #[cfg(feature = "parallel")]
    let arith = crate::par_izip!(
        a_coset.par_iter(),
        b_coset.par_iter(),
        c_coset.par_iter(),
        pi_coset,
    );
    let arith = arith
        .take(4 * n)
        .enumerate()
        .map(|(i, (a, b, c, pi))| {
            epk.arith.compute_quotient_i(
                i,
                *a,
                *b,
                *c,
                pi,
            )
        });

    #[cfg(not(feature = "parallel"))]
    let perm = itertools::izip!(
        a_coset.iter(),
        b_coset.iter(),
        c_coset.iter(),
        z1_coset.iter(),
        z1_coset.iter().skip(4),
        epk.l_1_coset.iter(),
    );
    #[cfg(feature = "parallel")]
    let perm = crate::par_izip!(
        a_coset.par_iter(),
        b_coset.par_iter(),
        c_coset.par_iter(),
        z1_coset.par_iter(),
        z1_coset.par_iter().skip(4),
        epk.l_1_coset.par_iter(),
    );
    let perm = perm
        .take(4 * n)
        .enumerate()
        .map(|(i, (a, b, c, z1, z1_next, l_1))| {
            epk.perm.compute_quotient_i(
                i,
                alpha,
                beta,
                gamma,
                *a,
                *b,
                *c,
                *z1,
                *z1_next,
                *l_1,
            )
        });

    #[cfg(not(feature = "parallel"))]
    let lookup = itertools::izip!(
        a_coset.iter(),
        b_coset.iter(),
        c_coset.iter(),
        f_coset,
        t_coset.iter(),
        t_coset.iter().skip(4),
        h1_coset.iter(),
        h1_coset.iter().skip(4),
        h2_coset,
        z2_coset.iter(),
        z2_coset.iter().skip(4),
        epk.l_1_coset.iter(),
    );
    #[cfg(feature = "parallel")]
    let lookup = crate::par_izip!(
        a_coset.par_iter(),
        b_coset.par_iter(),
        c_coset.par_iter(),
        f_coset,
        t_coset.par_iter(),
        t_coset.par_iter().skip(4),
        h1_coset.par_iter(),
        h1_coset.par_iter().skip(4),
        h2_coset,
        z2_coset.par_iter(),
        z2_coset.par_iter().skip(4),
        epk.l_1_coset.par_iter(),
    );
    let lookup = lookup
        .take(4 * n)
        .enumerate()
        .map(|(i, (a, b, c, f, t, t_next, h1, h1_next, h2, z2, z2_next, l_1))| {
            epk.lookup.compute_quotient_i(
                i,
                alpha,
                delta,
                epsilon,
                zeta,
                *a,
                *b,
                *c,
                f,
                *t,
                *t_next,
                *h1,
                *h1_next,
                h2,
                *z2,
                *z2_next,
                *l_1,
            )
        });

    #[cfg(not(feature = "parallel"))]
    let quotient = itertools::izip!(
        arith,
        perm,
        lookup,
        epk.vh_coset.iter(),
    );
    #[cfg(feature = "parallel")]
    let quotient = crate::par_izip!(
        arith,
        perm,
        lookup,
        epk.vh_coset.par_iter(),
    );
    let quotient = quotient
        .map(|(arith, perm, lookup, vh)| {
            (arith + perm + lookup) * vh.inverse().unwrap()
        })
        .collect();

    Ok(poly_from_coset_evals(&domain_4n, quotient))
}
