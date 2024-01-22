// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Prover-side of the PLONK Proving System

use std::rc::Rc;
use ark_std::cfg_iter_mut;
use ark_ff::{Field, FftField};
use ark_poly::{
    univariate::DensePolynomial,
    EvaluationDomain,
    UVPolynomial,
};
use ark_poly_commit::PCRandomness;
use itertools::Itertools;
use rand_core::{CryptoRng, RngCore};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

use crate::{
    commitment::HomomorphicCommitment,
    constraint_system::{ConstraintSystem, ProvingComposer, Variable},
    error::{to_pc_error, Error},
    lookup::{MultiSet, compute_z2_poly},
    permutation::compute_z1_poly,
    transcript::TranscriptProtocol,
    util::{EvaluationDomainExt, poly_from_evals_ref, evals_from_poly_ref},
    label_polynomial, label_commitment,
};
use super::{
    linearisation_poly, quotient_poly,
    ProverKey, ExtendedProverKey, VerifierKey, proof::Proof,
};

impl<F: Field> ProvingComposer<F> {
    /// Pads the circuit to the next power of two.
    ///
    /// # Note
    /// `n` is between circuit size and next power of two.
    fn pad_to(&mut self, n: usize) {
        assert!(n.is_power_of_two());
        assert!(n >= self.n);

        self.w_l.resize(n, Variable::Zero);
        self.w_r.resize(n, Variable::Zero);
        self.w_o.resize(n, Variable::Zero);
    }

    ///
    fn wire_evals(&self) -> (Vec<F>, Vec<F>, Vec<F>) {
        (
            self.w_l.iter().map(|var| self.var_map.value_of_var(*var)).collect(),
            self.w_r.iter().map(|var| self.var_map.value_of_var(*var)).collect(),
            self.w_o.iter().map(|var| self.var_map.value_of_var(*var)).collect(),
        )
    }
}

///
pub(crate) fn prove<F, D, PC, T, R>(
    ck: &PC::CommitterKey,
    pk: &ProverKey<F>,
    epk: Option<Rc<ExtendedProverKey<F>>>,
    vk: &VerifierKey<F, PC>,
    cs: ConstraintSystem<F>,
    transcript: &mut T,
    rng: &mut R,
) -> Result<Proof<F, D, PC>, Error>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    R: CryptoRng + RngCore,
{
    let n = cs.circuit_bound();

    let domain = D::new(n)
        .ok_or(Error::InvalidEvalDomainSize {
            log_size_of_group: n.trailing_zeros(),
            adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
        })?;
    assert_eq!(domain.size(), n);

    let mut composer: ProvingComposer<_> = cs.composer.into();
    // Pad composer
    composer.pad_to(n);

    let epk = if let Some(epk) = epk {
        epk
    } else {
        let sigma1 = evals_from_poly_ref(&domain, pk.perm.sigma1.polynomial());
        let sigma2 = evals_from_poly_ref(&domain, pk.perm.sigma2.polynomial());
        let sigma3 = evals_from_poly_ref(&domain, pk.perm.sigma3.polynomial());
        let q_lookup = evals_from_poly_ref(&domain, pk.lookup.q_lookup.polynomial());
        let epk = pk.extend_prover_key(
            &domain,
            sigma1,
            sigma2,
            sigma3,
            q_lookup,
        )?;
        Rc::new(epk)
    };

    // Since the caller is passing a pre-processed circuit
    // We assume that the Transcript has been seeded with the preprocessed
    // Commitments

    // Append Public Inputs to the transcript
    transcript.append_scalars("pi", composer.pi.get_vals());

    // 1. Compute witness Polynomials
    //
    // Convert Variables to scalars padding them to the
    // correct domain size.
    let (a_evals, b_evals, c_evals) = composer.wire_evals();

    // Witnesses are now in evaluation form, convert them to coefficients
    // so that we may commit to them.
    let mut a_poly = poly_from_evals_ref(&domain, &a_evals);
    let mut b_poly = poly_from_evals_ref(&domain, &b_evals);
    let mut c_poly = poly_from_evals_ref(&domain, &c_evals);

    // Add blinding factors
    add_blinders_to_poly(rng, 2, &mut a_poly);
    add_blinders_to_poly(rng, 2, &mut b_poly);
    add_blinders_to_poly(rng, 2, &mut c_poly);

    // Commit to witness polynomials.
    let labeled_a_poly = label_polynomial!(a_poly);
    let labeled_b_poly = label_polynomial!(b_poly);
    let labeled_c_poly = label_polynomial!(c_poly);
    let (labeled_wire_commits, _) =
        PC::commit(ck, vec![
            &labeled_a_poly,
            &labeled_b_poly,
            &labeled_c_poly,
        ], None)
        .map_err(to_pc_error::<F, PC>)?;

    // Add witness polynomial commitments to transcript.
    transcript.append_commitment("a_commit", labeled_wire_commits[0].commitment());
    transcript.append_commitment("b_commit", labeled_wire_commits[1].commitment());
    transcript.append_commitment("c_commit", labeled_wire_commits[2].commitment());

    // 2. Derive lookup polynomials

    // Compress lookup table into vector of single elements
    let t = cs.lookup_table.into_multiset(n);
    // Compute table poly
    let t_poly = t.clone().into_polynomial(&domain);

    // Compute query table f
    // When q_lookup[i] is zero the wire value is replaced with a dummy
    //   value currently set as the first row of the public table
    // If q_lookup[i] is one the wire values are preserved
    // This ensures the ith element of the compressed query table
    //   is an element of the compressed lookup table even when
    //   q_lookup[i] is 0 so the lookup check will pass

    let f: MultiSet<_> = c_evals
        .iter()
        .zip(epk.lookup.q_lookup.iter())
        .map(|(c, q_lookup)| if q_lookup.is_zero() { F::zero() } else { *c })
        .collect();
    // Compute s, as the sorted and concatenated version of f and t
    let (h1, h2) = t.combine_split(&f)?;

    // Compute h polys
    let mut h1_poly = h1.clone().into_polynomial(&domain);
    let mut h2_poly = h2.clone().into_polynomial(&domain);

    // Add blinding factors
    add_blinders_to_poly(rng, 3, &mut h1_poly);
    add_blinders_to_poly(rng, 2, &mut h2_poly);

    // Commit to t, h1 and h2 polys
    let labeled_t_poly = label_polynomial!(t_poly);
    let labeled_h1_poly = label_polynomial!(h1_poly);
    let labeled_h2_poly = label_polynomial!(h2_poly);
    // Commit to polynomials
    let (labeled_t_h_commits, _) =
        PC::commit(ck, vec![
            &labeled_t_poly,
            &labeled_h1_poly,
            &labeled_h2_poly
        ], None)
        .map_err(to_pc_error::<F, PC>)?;

    // Add commitments to transcript
    transcript.append_commitment("t_commit", labeled_t_h_commits[0].commitment());
    transcript.append_commitment("h1_commit", labeled_t_h_commits[1].commitment());
    transcript.append_commitment("h2_commit", labeled_t_h_commits[2].commitment());

    // 3. Compute permutation polynomial
    //
    // Compute permutation challenge `beta`.
    let beta = transcript.challenge_scalar("beta");

    // Compute permutation challenge `gamma`.
    let gamma = transcript.challenge_scalar("gamma");

    // Compute permutation challenge `delta`.
    let delta = transcript.challenge_scalar("delta");

    // Compute permutation challenge `epsilon`.
    let epsilon = transcript.challenge_scalar("epsilon");

    // Challenges must be different
    assert!(beta != gamma, "challenges must be different");
    assert!(beta != delta, "challenges must be different");
    assert!(beta != epsilon, "challenges must be different");
    assert!(gamma != delta, "challenges must be different");
    assert!(gamma != epsilon, "challenges must be different");
    assert!(delta != epsilon, "challenges must be different");

    let mut z1_poly = compute_z1_poly(
        &domain,
        beta,
        gamma,
        &a_evals,
        &b_evals,
        &c_evals,
        &epk.perm.sigma1,
        &epk.perm.sigma2,
        &epk.perm.sigma3,
    );
    drop(a_evals);
    drop(b_evals);
    drop(c_evals);

    // Add blinding factors
    add_blinders_to_poly(rng, 3, &mut z1_poly);

    // Compute mega permutation polynomial.
    // Compute lookup permutation poly
    let mut z2_poly = compute_z2_poly(
        &domain,
        delta,
        epsilon,
        &f,
        &t,
        &h1,
        &h2,
    );
    drop(f);
    drop(t);
    drop(h1);
    drop(h2);

    // Add blinding factors
    add_blinders_to_poly(rng, 3, &mut z2_poly);

    // Commit to permutation and lookup polynomials.
    let labeled_z1_poly = label_polynomial!(z1_poly);
    let labeled_z2_poly = label_polynomial!(z2_poly);
    let (labeled_z_commits, _) =
        PC::commit(ck, vec![&labeled_z1_poly, &labeled_z2_poly], None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add permutation polynomial commitment to transcript.
    transcript.append_commitment("z1_commit", labeled_z_commits[0].commitment());
    transcript.append_commitment("z2_commit", labeled_z_commits[1].commitment());

    // 3. Compute public inputs polynomial.
    let pi_poly = composer.pi.to_dense_poly(&domain);

    // 4. Compute quotient polynomial
    //
    // Compute quotient challenge; `alpha`, and gate-specific separation
    // challenges.
    let alpha = transcript.challenge_scalar("alpha");

    let q_poly = quotient_poly::compute(
        &domain,
        &epk,
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        labeled_z1_poly.polynomial(),
        labeled_z2_poly.polynomial(),
        labeled_a_poly.polynomial(),
        labeled_b_poly.polynomial(),
        labeled_c_poly.polynomial(),
        &pi_poly,
        labeled_h1_poly.polynomial(),
        labeled_h2_poly.polynomial(),
        &labeled_t_poly.polynomial(),
    )?;
    drop(pi_poly);

    // Split quotient polynomials
    let mut q_lo_poly =
        DensePolynomial::from_coefficients_slice(&q_poly[..(n + 2)]);
    let mut q_mid_poly =
        DensePolynomial::from_coefficients_slice(&q_poly[(n + 2)..2 * (n + 2)]);
    let mut q_hi_poly = 
        DensePolynomial::from_coefficients_slice(&q_poly[2 * (n + 2)..]);
    drop(q_poly);

    // Add blinding factors
    let (b0, b1) = (F::rand(rng), F::rand(rng));
    q_lo_poly.coeffs.push(b0);
    q_mid_poly.coeffs[0] -= b0;
    q_mid_poly.coeffs.push(b1);
    q_hi_poly.coeffs[0] -= b1;

    // Commit to splitted quotient polynomial
    let labeled_q_lo_poly = label_polynomial!(q_lo_poly);
    let labeled_q_mid_poly = label_polynomial!(q_mid_poly);
    let labeled_q_hi_poly = label_polynomial!(q_hi_poly);
    let (labeled_q_commits, _) =
        PC::commit(ck, vec![
            &labeled_q_lo_poly,
            &labeled_q_mid_poly,
            &labeled_q_hi_poly,
        ], None)
        .map_err(to_pc_error::<F, PC>)?;

    // Add quotient polynomial commitments to transcript
    transcript.append_commitment("q_lo_commit", labeled_q_commits[0].commitment());
    transcript.append_commitment("q_mid_commit", labeled_q_commits[1].commitment());
    transcript.append_commitment("q_hi_commit", labeled_q_commits[2].commitment());

    // 4. Compute linearisation polynomial
    //
    // Compute evaluation challenge ξ.
    let xi = transcript.challenge_scalar("xi");

    let (r_poly, evaluations) = linearisation_poly::compute(
        &domain,
        pk,
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        xi,
        labeled_a_poly.polynomial(),
        labeled_b_poly.polynomial(),
        labeled_c_poly.polynomial(),
        labeled_q_lo_poly.polynomial(),
        labeled_q_mid_poly.polynomial(),
        labeled_q_hi_poly.polynomial(),
        labeled_z1_poly.polynomial(),
        labeled_z2_poly.polynomial(),
        labeled_h1_poly.polynomial(),
        labeled_h2_poly.polynomial(),
        &labeled_t_poly.polynomial(),
    );
    drop(labeled_q_lo_poly);
    drop(labeled_q_mid_poly);
    drop(labeled_q_hi_poly);

    // Add evaluations to transcript.
    // First wire evals
    transcript.append_scalar("a_eval", &evaluations.wire_evals.a);
    transcript.append_scalar("b_eval", &evaluations.wire_evals.b);
    transcript.append_scalar("c_eval", &evaluations.wire_evals.c);

    // Second permutation evals
    transcript.append_scalar("sigma1_eval", &evaluations.perm_evals.sigma1);
    transcript.append_scalar("sigma2_eval", &evaluations.perm_evals.sigma2);
    transcript.append_scalar("z1_next_eval", &evaluations.perm_evals.z1_next);

    // Third lookup evals
    transcript.append_scalar("q_lookup_eval", &evaluations.lookup_evals.q_lookup);
    transcript.append_scalar("t_eval", &evaluations.lookup_evals.t);
    transcript.append_scalar("t_next_eval", &evaluations.lookup_evals.t_next);
    transcript.append_scalar("z2_next_eval", &evaluations.lookup_evals.z2_next);
    transcript.append_scalar("h1_next_eval", &evaluations.lookup_evals.h1_next);
    transcript.append_scalar("h2_eval", &evaluations.lookup_evals.h2);

    // 5. Compute Openings using KZG10
    //
    // We merge the quotient polynomial using the `ξ` so the SRS
    // is linear in the circuit size `n`

    // Compute aggregate witness to polynomials evaluated at the evaluation challenge `ξ`
    let eta = transcript.challenge_scalar("eta");

    let labeled_r_poly = label_polynomial!(r_poly);
    let (labeled_r_commit, _) =
        PC::commit(ck, vec![&labeled_r_poly], None)
            .map_err(to_pc_error::<F, PC>)?;

    let labeled_sigma1_commit = label_commitment!(vk.perm.sigma1);
    let labeled_sigma2_commit = label_commitment!(vk.perm.sigma2);
    let labeled_q_lookup_commit = label_commitment!(vk.lookup.q_lookup);
    let randomness = <PC::Randomness as PCRandomness>::empty();
    let aw_opening = PC::open(
        ck,
        vec![
            &labeled_r_poly,
            &labeled_a_poly,
            &labeled_b_poly,
            &labeled_c_poly,
            &pk.perm.sigma1,
            &pk.perm.sigma2,
            &pk.lookup.q_lookup,
            &labeled_t_poly,
            &labeled_h2_poly,
        ],
        vec![
            &labeled_r_commit[0],
            &labeled_wire_commits[0],
            &labeled_wire_commits[1],
            &labeled_wire_commits[2],
            &labeled_sigma1_commit,
            &labeled_sigma2_commit,
            &labeled_q_lookup_commit,
            &labeled_t_h_commits[0],
            &labeled_t_h_commits[2],
        ],
        &xi,
        eta,
        vec![
            &randomness,
            &randomness,
            &randomness,
            &randomness,
            &randomness,
            &randomness,
            &randomness,
            &randomness,
            &randomness,
        ],
        None,
    )
    .map_err(to_pc_error::<F, PC>)?;
    drop(labeled_r_poly);
    drop(labeled_a_poly);
    drop(labeled_b_poly);
    drop(labeled_c_poly);
    drop(labeled_h2_poly);

    let saw_opening = PC::open(
        ck,
        vec![
            &labeled_t_poly,
            &labeled_z1_poly,
            &labeled_z2_poly,
            &labeled_h1_poly,
        ],
        vec![
            &labeled_t_h_commits[0],
            &labeled_z_commits[0],
            &labeled_z_commits[1],
            &labeled_t_h_commits[1],
        ],
        &(xi * domain.group_gen()),
        eta,
        vec![&randomness, &randomness, &randomness],
        None,
    )
    .map_err(to_pc_error::<F, PC>)?;

    Ok(Proof {
        a_commit: labeled_wire_commits[0].commitment().clone(),
        b_commit: labeled_wire_commits[1].commitment().clone(),
        c_commit: labeled_wire_commits[2].commitment().clone(),
        t_commit: labeled_t_h_commits[0].commitment().clone(),
        h1_commit: labeled_t_h_commits[1].commitment().clone(),
        h2_commit: labeled_t_h_commits[2].commitment().clone(),
        z1_commit: labeled_z_commits[0].commitment().clone(),
        z2_commit: labeled_z_commits[1].commitment().clone(),
        q_lo_commit: labeled_q_commits[0].commitment().clone(),
        q_mid_commit: labeled_q_commits[1].commitment().clone(),
        q_hi_commit: labeled_q_commits[2].commitment().clone(),
        aw_opening,
        saw_opening,
        evaluations,
        _p: Default::default(),
    })
}

fn add_blinders_to_poly<F, R>(rng: &mut R, k: usize, poly: &mut DensePolynomial<F>)
where
    F: Field,
    R: RngCore + CryptoRng,
{
    let blinders = (0..k).into_iter().map(|_| F::rand(rng)).collect_vec();
    poly.coeffs.extend_from_slice(&blinders);
    
    cfg_iter_mut!(poly.coeffs)
        .zip(blinders)
        .for_each(|(coeff, blinder)| coeff.sub_assign(blinder));
}

#[cfg(test)]
mod test {
    use ark_ff::FftField;
    use ark_poly::{GeneralEvaluationDomain, EvaluationDomain, Polynomial};
    use ark_std::test_rng;
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_377::Bls12_377;
    use itertools::Itertools;
    
    use crate::{util::poly_from_evals_ref, batch_test_field};
    use super::add_blinders_to_poly;

    fn test_add_blinders_to_poly<F: FftField>() {
        let rng = &mut test_rng();
        // 8 degree poly
        let domain = GeneralEvaluationDomain::new(8).unwrap();
        let evals = (0..8).into_iter().map(|_| F::rand(rng)).collect_vec();
        let poly = poly_from_evals_ref(&domain, &evals);

        // add 1 blinder
        let mut poly_1 = poly.clone();
        add_blinders_to_poly(rng, 1, &mut poly_1);
        for (ele, expect) in domain.elements().zip(evals.iter()) {
            let res = poly_1.evaluate(&ele);
            assert_eq!(&res, expect);
        }
        // add 2 blinders
        let mut poly_2 = poly.clone();
        add_blinders_to_poly(rng, 2, &mut poly_2);
        for (ele, expect) in domain.elements().zip(evals.iter()) {
            let res = poly_2.evaluate(&ele);
            assert_eq!(&res, expect);
        }
        // add 3 blinders
        let mut poly_3 = poly.clone();
        add_blinders_to_poly(rng, 3, &mut poly_3);
        for (ele, expect) in domain.elements().zip(evals.iter()) {
            let res = poly_3.evaluate(&ele);
            assert_eq!(&res, expect);
        }
    }

    batch_test_field!(
        Bn254,
        [test_add_blinders_to_poly],
        []
    );

    batch_test_field!(
        Bls12_377,
        [test_add_blinders_to_poly],
        []
    );

    batch_test_field!(
        Bls12_381,
        [test_add_blinders_to_poly],
        []
    );
}