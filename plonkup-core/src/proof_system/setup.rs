// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Methods to preprocess the constraint system for use in a proof.

use ark_ff::{FftField, Field};
use ark_poly::EvaluationDomain;
use itertools::Itertools;

use crate::{
    commitment::HomomorphicCommitment,
    constraint_system::{ConstraintSystem, SetupComposer},
    error::{to_pc_error, Error},
    label_polynomial,
    proof_system::{ProverKey, ExtendedProverKey, VerifierKey},
    util::{poly_from_evals, poly_from_evals_ref},
};

impl<F: Field> SetupComposer<F> {
    /// Pads the circuit to the next power of two.
    ///
    /// # Note
    /// `n` is between circuit size and next power of two.
    fn pad_to(&mut self, n: usize) {
        assert!(n.is_power_of_two());
        assert!(n >= self.n);

        self.q_m.resize(n, F::zero());
        self.q_l.resize(n, F::zero());
        self.q_r.resize(n, F::zero());
        self.q_o.resize(n, F::zero());
        self.q_c.resize(n, F::zero());
        self.q_lookup.resize(n, F::zero());
        self.t_tag.resize(n, F::zero());
    }
}

///
#[allow(clippy::type_complexity)]
pub(crate) fn setup<F, D, PC>(
    ck: &PC::CommitterKey,
    cs: ConstraintSystem<F>,
    extend: bool,
) -> Result<
    (
        ProverKey<F>,
        Option<ExtendedProverKey<F>>,
        VerifierKey<F, PC>,
    ),
    Error
>
where
    F: FftField,
    D: EvaluationDomain<F>,
    PC: HomomorphicCommitment<F>,
{
    let n = cs.circuit_bound();

    let domain = D::new(n)
        .ok_or(Error::InvalidEvalDomainSize {
            log_size_of_group: n.trailing_zeros(),
            adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
        })?;
    assert_eq!(domain.size(), n);

    let mut composer: SetupComposer<F> = cs.composer.into();
    // Pad composer
    composer.pad_to(n);

    let q_m_poly = poly_from_evals(&domain, composer.q_m);
    let q_l_poly = poly_from_evals(&domain, composer.q_l);
    let q_r_poly = poly_from_evals(&domain, composer.q_r);
    let q_o_poly = poly_from_evals(&domain, composer.q_o);
    let q_c_poly = poly_from_evals(&domain, composer.q_c);
    let q_lookup_poly = poly_from_evals_ref(&domain, &composer.q_lookup);
    let t_tag_poly = poly_from_evals_ref(&domain, &composer.t_tag);

    // 2. Compute the sigma polynomials
    let roots = domain.elements().collect_vec();
    let (sigma1_evals, sigma2_evals, sigma3_evals) =
        composer.perm.compute_all_sigma_evals(n, &roots);

    let sigma1_poly = poly_from_evals_ref(&domain, &sigma1_evals);
    let sigma2_poly = poly_from_evals_ref(&domain, &sigma2_evals);
    let sigma3_poly = poly_from_evals_ref(&domain, &sigma3_evals);

    // 3. Compute lookup table polynomials
    let mut t_polys = cs.lookup_table.into_polynomials(&domain);
    let t4_poly = t_polys.pop().unwrap();
    let t3_poly = t_polys.pop().unwrap();
    let t2_poly = t_polys.pop().unwrap();
    let t1_poly = t_polys.pop().unwrap();

    let labeled_q_m_poly = label_polynomial!(q_m_poly);
    let labeled_q_l_poly = label_polynomial!(q_l_poly);
    let labeled_q_r_poly = label_polynomial!(q_r_poly);
    let labeled_q_o_poly = label_polynomial!(q_o_poly);
    let labeled_q_c_poly = label_polynomial!(q_c_poly);
    let labeled_q_lookup_poly = label_polynomial!(q_lookup_poly);
    let labeled_t_tag_poly = label_polynomial!(t_tag_poly);
    let labeled_sigma1_poly = label_polynomial!(sigma1_poly);
    let labeled_sigma2_poly = label_polynomial!(sigma2_poly);
    let labeled_sigma3_poly = label_polynomial!(sigma3_poly);
    let labeled_t1_poly = label_polynomial!(t1_poly);
    let labeled_t2_poly = label_polynomial!(t2_poly);
    let labeled_t3_poly = label_polynomial!(t3_poly);
    let labeled_t4_poly = label_polynomial!(t4_poly);

    let (labeled_commits, _) =
        PC::commit(
            ck,
            vec![
                &labeled_q_m_poly,
                &labeled_q_l_poly,
                &labeled_q_r_poly,
                &labeled_q_o_poly,
                &labeled_q_c_poly,
                &labeled_q_lookup_poly,
                &labeled_t_tag_poly,
                &labeled_sigma1_poly,
                &labeled_sigma2_poly,
                &labeled_sigma3_poly,
                &labeled_t1_poly,
                &labeled_t2_poly,
                &labeled_t3_poly,
                &labeled_t4_poly,
            ],
            None,
        )
        .map_err(to_pc_error::<F, PC>)?;
    drop(labeled_t1_poly);
    drop(labeled_t2_poly);
    drop(labeled_t3_poly);
    drop(labeled_t4_poly);

    let pi_roots = composer.pp.get_pos().map(|i| domain.element(*i)).collect();
    let vk = VerifierKey::from_polynomial_commitments(
        n,
        pi_roots,
        labeled_commits[0].commitment().clone(), // q_m
        labeled_commits[1].commitment().clone(), // q_l
        labeled_commits[2].commitment().clone(), // q_r
        labeled_commits[3].commitment().clone(), // q_o
        labeled_commits[4].commitment().clone(), // q_c
        labeled_commits[5].commitment().clone(), // q_lookup
        labeled_commits[6].commitment().clone(), // t_tag
        labeled_commits[7].commitment().clone(), // sigma1
        labeled_commits[8].commitment().clone(), // sigma2
        labeled_commits[9].commitment().clone(), // sigma3
        labeled_commits[10].commitment().clone(), // t1
        labeled_commits[11].commitment().clone(), // t2
        labeled_commits[12].commitment().clone(), // t3
        labeled_commits[13].commitment().clone(), // t4
    );

    let pk = ProverKey::from_polynomials(
        labeled_q_m_poly,
        labeled_q_l_poly,
        labeled_q_r_poly,
        labeled_q_o_poly,
        labeled_q_c_poly,
        labeled_q_lookup_poly,
        labeled_t_tag_poly,
        labeled_sigma1_poly,
        labeled_sigma2_poly,
        labeled_sigma3_poly,
    );

    let epk = if extend {
        let epk = pk.extend_prover_key(
            &domain,
            sigma1_evals,
            sigma2_evals,
            sigma3_evals,
            composer.q_lookup,
            composer.t_tag,
        )?;
        Some(epk)
    } else {
        None
    };

    Ok((pk, epk, vk))
}
