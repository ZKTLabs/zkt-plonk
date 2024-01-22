// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the lookups.

mod table;
mod multiset;

pub(crate) use multiset::MultiSet;

pub use table::*;

use ark_std::cfg_iter;
use ark_ff::FftField;
use ark_poly::{univariate::DensePolynomial, EvaluationDomain};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::util::poly_from_evals;

/// Compute the `z2` polynomial.
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

    let t_next = cfg_iter!(t).skip(1);
    let h1_next = cfg_iter!(h1).skip(1);

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
                * (delta * t_next + epsilon_one_plus_delta + t);
            let dominator = (delta * h2 + epsilon_one_plus_delta + h1)
                * (delta * h1_next + epsilon_one_plus_delta + h2);

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

#[cfg(test)]
mod test {
    use ark_ff::FftField;
    use ark_bn254::Bn254;
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, Polynomial};
    use ark_std::test_rng;
    use itertools::{izip, Itertools};

    use crate::{
        util::{EvaluationDomainExt, poly_from_evals_ref},
        batch_test_field,
    };
    use super::*;

    fn test_compute_z2_poly<F: FftField>() {
        let rng = &mut test_rng();

        // t = {0, 0, 1, 2, 3, 4, 5, 6}
        let t = MultiSet(vec![
            F::from(0u64),
            F::from(0u64),
            F::from(1u64),
            F::from(2u64),
            F::from(3u64),
            F::from(4u64),
            F::from(5u64),
            F::from(6u64),
        ]);

        // f = {3, 6, 0, 5, 4, 3, 2, 0}
        let f = MultiSet(vec![
            F::from(3u64),
            F::from(6u64),
            F::from(0u64),
            F::from(5u64),
            F::from(4u64),
            F::from(3u64),
            F::from(2u64),
            F::from(0u64),
        ]);

        let (h1, h2) = t.combine_split(&f).unwrap();

        let domain = GeneralEvaluationDomain::new(8).unwrap();
        let roots = domain.elements().collect_vec();

        let delta = F::rand(rng);
        let epsilon = F::rand(rng);
        let z2_poly = compute_z2_poly(
            &domain,
            delta,
            epsilon,
            &f.0,
            &t.0,
            &h1.0,
            &h2.0,
        );
        let t_poly = poly_from_evals_ref(&domain, &t);
        let h1_poly = poly_from_evals_ref(&domain, &h1);

        let omega = domain.group_gen();
        let one_plus_delta = F::one() + delta;
        let epsilon_one_plus_delta = epsilon * one_plus_delta;
        izip!(roots.iter(), t.iter(), f.iter(), h1.iter(), h2.iter())
            .for_each(|(root, t, f, h1, h2)| {
                let part_1 = one_plus_delta
                    * (epsilon + f)
                    * (delta * t_poly.evaluate(&(omega * root)) + epsilon_one_plus_delta + t)
                    * z2_poly.evaluate(root);
                let part_2 = (delta * h2 + epsilon_one_plus_delta + h1)
                    * (delta * h1_poly.evaluate(&(omega * root)) + epsilon_one_plus_delta + h2)
                    * z2_poly.evaluate(&(omega * root));
                assert_eq!(part_1, part_2);
            });

        let root_0 = roots[0];
        assert_eq!(z2_poly.evaluate(&root_0), F::one());
    }

    batch_test_field!(
        Bn254,
        [test_compute_z2_poly],
        []
    );
}
