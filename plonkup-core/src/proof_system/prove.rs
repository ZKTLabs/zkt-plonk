// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Prover-side of the PLONK Proving System

use std::rc::Rc;
use ark_ff::{Field, FftField};
use ark_poly::{
    Polynomial,
    univariate::DensePolynomial,
    EvaluationDomain,
    UVPolynomial,
};
use itertools::{izip, Itertools};
use rand_core::{CryptoRng, RngCore};

use crate::{
    commitment::HomomorphicCommitment,
    constraint_system::{ConstraintSystem, ProvingComposer, Variable},
    error::{to_pc_error, Error},
    label_polynomial,
    lookup::MultiSet,
    permutation::{compute_z1_poly, compute_z2_poly},
    transcript::TranscriptProtocol,
    util::{
        EvaluationDomainExt,
        lc, compute_lagrange_poly, poly_from_evals_ref, evals_from_poly_ref,
    },
};

use super::{
    linearisation_poly, quotient_poly,
    ProverKey, ExtendedProverKey,
    proof::Proof,
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
            log_size_of_group: cs.circuit_bound().trailing_zeros(),
            adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
        })?;
    assert_eq!(domain.size(), n);

    let mut composer: ProvingComposer<_> = cs.composer.into();
    // Pad composer
    composer.pad_to(n);

    let epk = if let Some(epk) = epk {
        epk
    } else {
        let sigma1 = evals_from_poly_ref(&domain, &pk.perm.sigma1);
        let sigma2 = evals_from_poly_ref(&domain, &pk.perm.sigma2);
        let sigma3 = evals_from_poly_ref(&domain, &pk.perm.sigma3);
        let q_lookup = evals_from_poly_ref(&domain, &pk.lookup.q_lookup);
        let t_tag = evals_from_poly_ref(&domain, &pk.lookup.t_tag);
        let lagranges = composer
            .pi
            .get_pos()
            .into_iter()
            .map(|index| compute_lagrange_poly(&domain, *index))
            .collect();
        let epk = pk.extend_prover_key(
            &domain,
            sigma1,
            sigma2,
            sigma3,
            q_lookup,
            t_tag,
            lagranges,
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
    add_blinders_to_poly(rng, &mut a_poly, n, 2);
    add_blinders_to_poly(rng, &mut b_poly, n, 2);
    add_blinders_to_poly(rng, &mut c_poly, n, 2);

    let wire_polys = vec![
        label_polynomial!(a_poly),
        label_polynomial!(b_poly),
        label_polynomial!(c_poly),
    ];

    // Commit to witness polynomials.
    let (wire_commits, wire_rands) =
        PC::commit(ck, &wire_polys, None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add witness polynomial commitments to transcript.
    transcript.append_commitment("a_commit", wire_commits[0].commitment());
    transcript.append_commitment("b_commit", wire_commits[1].commitment());
    transcript.append_commitment("c_commit", wire_commits[2].commitment());

    // 2. Derive lookup polynomials

    // Generate table compression factor
    let zeta = transcript.challenge_scalar("zeta");

    // Compress lookup table into vector of single elements
    let t = cs.lookup_table.compress_to_multiset(n, zeta);
    // Compute table poly
    let t_poly = t.clone().into_polynomial(&domain);

    // Compute query table f
    // When q_lookup[i] is zero the wire value is replaced with a dummy
    //   value currently set as the first row of the public table
    // If q_lookup[i] is one the wire values are preserved
    // This ensures the ith element of the compressed query table
    //   is an element of the compressed lookup table even when
    //   q_lookup[i] is 0 so the lookup check will pass

    let t_first = t.0[0];
    let f_args = izip!(
        &a_evals,
        &b_evals,
        &c_evals,
        &epk.lookup.q_lookup,
        &epk.lookup.t_tag,
    );
    let f = f_args
        .map(|(a, b, c, q_lookup, t_tag)| {
            if q_lookup.is_zero() {
                t_first
            } else {
                lc(&[*a, *b, *c, *t_tag], zeta)
            }
        })
        .collect::<MultiSet<_>>();

    // Compute query poly
    let mut f_poly = f.clone().into_polynomial(&domain);

    // Add blinding factors
    add_blinders_to_poly(rng, &mut f_poly, n, 2);

    let mut f_poly = vec![label_polynomial!(f_poly)];
    // Commit to query polynomial
    let (f_commit, _) =
        PC::commit(ck, &f_poly, None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add f_poly commitment to transcript
    transcript.append_commitment("f_commit", f_commit[0].commitment());

    // Compute s, as the sorted and concatenated version of f and t
    let (h1, h2) = t.combine_split(&f)?;

    // Compute h polys
    let mut h1_poly = h1.clone().into_polynomial(&domain);
    let mut h2_poly = h2.clone().into_polynomial(&domain);

    // Add blinding factors
    add_blinders_to_poly(rng, &mut h1_poly, n, 3);
    add_blinders_to_poly(rng, &mut h2_poly, n, 2);

    // Commit to h polys
    let mut h1_poly = vec![label_polynomial!(h1_poly)];
    let mut h2_poly = vec![label_polynomial!(h2_poly)];
    let (h1_commit, _) =
        PC::commit(ck, &h1_poly, None)
            .map_err(to_pc_error::<F, PC>)?;
    let (h2_commit, _) =
        PC::commit(ck, &h2_poly, None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add h polynomials to transcript
    transcript.append_commitment("h1_commit", h1_commit[0].commitment());
    transcript.append_commitment("h2_commit", h2_commit[0].commitment());

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
    add_blinders_to_poly(rng, &mut z1_poly, n, 3);

    // Commit to permutation polynomial.
    let mut z1_poly = vec![label_polynomial!(z1_poly)];
    let (z1_commit, _) =
        PC::commit(ck, &z1_poly, None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add permutation polynomial commitment to transcript.
    transcript.append_commitment("z1_commit", z1_commit[0].commitment());

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
    add_blinders_to_poly(rng, &mut z2_poly, n, 3);

    // Commit to lookup permutation polynomial.
    let mut z2_poly = vec![label_polynomial!(z2_poly)];
    let (z2_commit, _) =
        PC::commit(ck, &z2_poly, None)
            .map_err(to_pc_error::<F, PC>)?;

    transcript.append_commitment("z2_commit", z2_commit[0].commitment());

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
        zeta,
        z1_poly[0].polynomial(),
        z2_poly[0].polynomial(),
        wire_polys[0].polynomial(),
        wire_polys[1].polynomial(),
        wire_polys[2].polynomial(),
        &pi_poly,
        f_poly[0].polynomial(),
        h1_poly[0].polynomial(),
        h2_poly[0].polynomial(),
        &t_poly,
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

    let q_polys = vec![
        label_polynomial!(q_lo_poly),
        label_polynomial!(q_mid_poly),
        label_polynomial!(q_hi_poly),
    ];
    // Commit to splitted quotient polynomial
    let (q_commits, _) =
        PC::commit(ck, &q_polys, None)
            .map_err(to_pc_error::<F, PC>)?;

    // Add quotient polynomial commitments to transcript
    transcript.append_commitment("q_lo_commit", q_commits[0].commitment());
    transcript.append_commitment("q_mid_commit", q_commits[1].commitment());
    transcript.append_commitment("q_hi_commit", q_commits[2].commitment());

    // 4. Compute linearisation polynomial
    //
    // Compute evaluation challenge; `z`.
    let z = transcript.challenge_scalar("z");

    let (linear_poly, evaluations) = linearisation_poly::compute(
        &domain,
        pk,
        &epk,
        composer.pi.get_vals(),
        alpha,
        beta,
        gamma,
        delta,
        epsilon,
        zeta,
        z,
        wire_polys[0].polynomial(),
        wire_polys[1].polynomial(),
        wire_polys[2].polynomial(),
        q_polys[0].polynomial(),
        q_polys[1].polynomial(),
        q_polys[2].polynomial(),
        z1_poly[0].polynomial(),
        z2_poly[0].polynomial(),
        f_poly[0].polynomial(),
        h1_poly[0].polynomial(),
        h2_poly[0].polynomial(),
        &t_poly,
    )?;
    drop(q_polys);

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
    transcript.append_scalar("t_tag_eval", &evaluations.lookup_evals.t_tag);
    transcript.append_scalar("f_eval", &evaluations.lookup_evals.f);
    transcript.append_scalar("t_eval", &evaluations.lookup_evals.t);
    transcript.append_scalar("t_next_eval", &evaluations.lookup_evals.t_next);
    transcript.append_scalar("z2_next_eval", &evaluations.lookup_evals.z2_next);
    transcript.append_scalar("h1_next_eval", &evaluations.lookup_evals.h1_next);
    transcript.append_scalar("h2_eval", &evaluations.lookup_evals.h2);

    // 5. Compute Openings using KZG10
    //
    // We merge the quotient polynomial using the `z_challenge` so the SRS
    // is linear in the circuit size `n`

    // Compute aggregate witness to polynomials evaluated at the evaluation
    // challenge `z`
    let v = transcript.challenge_scalar("v");

    // XXX: The quotient polynmials is used here and then in the
    // opening poly. It is being left in for now but it may not
    // be necessary. Warrants further investigation.
    // Ditto with the out_sigma poly.
    let mut opening_polys = vec![
        label_polynomial!(linear_poly),
        label_polynomial!(pk.perm.sigma1.clone()),
        label_polynomial!(pk.perm.sigma2.clone()),
        label_polynomial!(pk.lookup.t_tag.clone()),
        f_poly.pop().unwrap(),
        h2_poly.pop().unwrap(),
        label_polynomial!(t_poly),
    ];

    let (aw_commits, aw_rands) =
        PC::commit(ck, &opening_polys, None)
            .map_err(to_pc_error::<F, PC>)?;

    let aw_opening = PC::open(
        ck,
        opening_polys.iter().chain(wire_polys.iter()),
        aw_commits.iter().chain(wire_commits.iter()),
        &z,
        v,
        aw_rands.iter().chain(wire_rands.iter()),
        None,
    )
    .map_err(to_pc_error::<F, PC>)?;

    let opening_polys = vec![
        z1_poly.pop().unwrap(),
        opening_polys.pop().unwrap(),
        z2_poly.pop().unwrap(),
        h1_poly.pop().unwrap(),
    ];

    let (saw_commits, saw_rands) =
        PC::commit(ck, &opening_polys, None)
            .map_err(to_pc_error::<F, PC>)?;

    let saw_opening = PC::open(
        ck,
        &opening_polys,
        &saw_commits,
        &(z * domain.group_gen()),
        v,
        &saw_rands,
        None,
    )
    .map_err(to_pc_error::<F, PC>)?;

    Ok(Proof {
        a_commit: wire_commits[0].commitment().clone(),
        b_commit: wire_commits[1].commitment().clone(),
        c_commit: wire_commits[2].commitment().clone(),
        f_commit: f_commit[0].commitment().clone(),
        h1_commit: h1_commit[0].commitment().clone(),
        h2_commit: h2_commit[0].commitment().clone(),
        z1_commit: z1_commit[0].commitment().clone(),
        z2_commit: z2_commit[0].commitment().clone(),
        q_lo_commit: q_commits[0].commitment().clone(),
        q_mid_commit: q_commits[1].commitment().clone(),
        q_hi_commit: q_commits[2].commitment().clone(),
        aw_opening,
        saw_opening,
        evaluations,
        _p: Default::default(),
    })
}

fn add_blinders_to_poly<F, R>(
    rng: &mut R,
    poly: &mut DensePolynomial<F>,
    n: usize,
    k: usize,
)
where
    F: Field,
    R: RngCore + CryptoRng,
{
    assert_eq!(poly.degree(), n);
    poly.coeffs.resize(n + k, F::zero());

    let blinders = (0..k).into_iter().map(|_| F::rand(rng)).collect_vec();

    poly
        .coeffs
        .iter_mut()
        .zip(blinders.iter())
        .for_each(|(coeff, blinder)| coeff.sub_assign(blinder));

    poly
        .coeffs
        .iter_mut()
        .skip(n)
        .zip(blinders.iter())
        .for_each(|(coeff, blinder)| coeff.add_assign(blinder));
}