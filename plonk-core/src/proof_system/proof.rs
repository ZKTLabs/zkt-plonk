// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A Proof stores the commitments to all of the elements that are needed to
//! univocally identify a prove of some statement.
//!
//! This module contains the implementation of the `ConstraintSystem`s [`Proof`]
//! structure and it's methods.

use std::marker::PhantomData;
use ark_ff::{Field, FftField};
use ark_poly::EvaluationDomain;
use ark_serialize::*;

use crate::{
    label_commitment,
    commitment::HomomorphicCommitment,
    proof_system::VerifierKey,
    transcript::TranscriptProtocol,
    util::{EvaluationDomainExt, compute_lagrange_evaluation},
    error::Error,
};

/// Subset of the [`ProofEvaluations`]. Evaluations at `z` of the
/// wire polynomials
#[derive(Debug, Clone, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
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
#[derive(Debug, Clone, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct PermutationEvaluations<F: Field> {
    /// Evaluation of the left sigma polynomial at `z`.
    pub sigma1: F,

    /// Evaluation of the right sigma polynomial at `z`.
    pub sigma2: F,

    /// Evaluation of the permutation polynomial at `z * omega` where `omega`
    /// is a root of unity.
    pub z1_next: F,
}

/// Probably all of these should go into CustomEvals
#[derive(Debug, Clone, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct LookupEvaluations<F: Field> {
    /// Evaluations of the query polynomial at `q_lookup`
    pub q_lookup: F,

    /// Evaluations of the table polynomial at `z`
    pub t: F,

    /// (Shifted) Evaluation of the table polynomial at `z * root of unity`
    pub t_next: F,

    /// (Shifted) Evaluation of the lookup permutation polynomial at `z * root
    /// of unity`
    pub z2_next: F,

    /// (Shifted) Evaluation of the even indexed half of sorted plonkup poly
    /// at `z root of unity
    pub h1_next: F,

    /// Evaluations of the odd indexed half of sorted plonkup poly at `z
    /// root of unity
    pub h2: F,
}

/// Set of evaluations that form the [`Proof`](super::Proof).
#[derive(Debug, Clone, Default, Eq, PartialEq, CanonicalDeserialize, CanonicalSerialize)]
pub struct ProofEvaluations<F: Field> {
    /// Wire evaluations
    pub wire_evals: WireEvaluations<F>,

    /// Permutation and sigma polynomials evaluations
    pub perm_evals: PermutationEvaluations<F>,

    /// Lookup evaluations
    pub lookup_evals: LookupEvaluations<F>,
}

/// A [`Proof`] is a composition of `Commitment`s to the Witness, Permutation,
/// Quotient, Shifted and Opening polynomials as well as the
/// `ProofEvaluations`.
/// Set of evaluations that form the [`Proof`](super::Proof).
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = "PC::Commitment: Clone, PC::Proof: Clone"),
    Debug(bound = "PC::Commitment: core::fmt::Debug, PC::Proof: core::fmt::Debug"),
    Default(bound = "PC::Commitment: Default, PC::Proof: Default"),
    Eq(bound = "PC::Commitment: Eq, PC::Proof: Eq"),
    PartialEq(bound = "PC::Commitment: PartialEq, PC::Proof: PartialEq")
)]
pub struct Proof<F, D, PC>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
{
    /// Commitment to the witness polynomial for the left wires.
    pub a_commit: PC::Commitment,

    /// Commitment to the witness polynomial for the right wires.
    pub b_commit: PC::Commitment,

    /// Commitment to the witness polynomial for the output wires.
    pub c_commit: PC::Commitment,

    /// Commitmet to the table polynomial.
    pub t_commit: PC::Commitment,

    /// Commitment to first half of sorted polynomial
    pub h1_commit: PC::Commitment,

    /// Commitment to second half of sorted polynomial
    pub h2_commit: PC::Commitment,

    /// Commitment to the permutation polynomial.
    pub z1_commit: PC::Commitment,

    /// Commitment to the lookup permutation polynomial.
    pub z2_commit: PC::Commitment,

    /// Commitment to the quotient polynomial.
    pub q_lo_commit: PC::Commitment,

    /// Commitment to the quotient polynomial.
    pub q_mid_commit: PC::Commitment,

    /// Commitment to the quotient polynomial.
    pub q_hi_commit: PC::Commitment,

    /// Batch opening proof of the aggregated witnesses
    pub aw_opening: PC::Proof,

    /// Batch opening proof of the shifted aggregated witnesses
    pub saw_opening: PC::Proof,

    /// Subset of all of the evaluations added to the proof.
    pub evaluations: ProofEvaluations<F>,

    pub(super) _p: PhantomData<D>,
}

impl<F, D, PC> Proof<F, D, PC>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
{
    fn compute_r0(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
        epsilon: F,
        xi: F,
        l_1_eval: F,
        zh_eval: F,
        pub_inputs: &[F],
        vk: &VerifierKey<F, PC>,
    ) -> F {
        let alpha_sq = alpha.square();

        // PI(ξ)
        let part_1 = pub_inputs
            .iter()
            .zip(vk.pi_roots.iter())
            .map(|(pi, point)| {
                let lagrange = compute_lagrange_evaluation(
                    vk.n,
                    *point,
                    zh_eval,
                    xi,
                );
                lagrange * pi
            })
            .sum::<F>()
            .neg();

        // (a(ξ) + β*σ1(ξ) + γ) * (b(ξ) + β*σ2(ξ) + γ) * (c(ξ) + γ) * α * z1(ωξ)
        let part_2 = alpha * self.evaluations.perm_evals.z1_next
            * (self.evaluations.wire_evals.a + beta * self.evaluations.perm_evals.sigma1 + gamma)
            * (self.evaluations.wire_evals.b + beta * self.evaluations.perm_evals.sigma2 + gamma)
            * (self.evaluations.wire_evals.c + gamma);

        // L_1(ξ) * α^2
        let part_3 = l_1_eval * alpha_sq;

        // α^3 * z2(ωξ) * (ε(1+δ) + δ * h2(ξ)) * (ε(1+δ) + h2(ξ) + δ * h1(ωξ))
        let part_4 = {
            let epsilon_one_plus_delta = epsilon * (F::one() + delta);
            alpha_sq * alpha
                * self.evaluations.lookup_evals.z2_next
                * (epsilon_one_plus_delta + delta * self.evaluations.lookup_evals.h2)
                * (epsilon_one_plus_delta + self.evaluations.lookup_evals.h2 + delta * self.evaluations.lookup_evals.h1_next)
        };

        // L_1(z) * α^4
        let part_5 = l_1_eval * alpha_sq.square();

        // Return r_0
        part_1 + part_2 + part_3 + part_4 + part_5
    }

    /// Computes the commitment to `[r]_1`.
    fn compute_linearisation_commitment(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
        epsilon: F,
        xi: F,
        l_1_eval: F,
        zh_eval: F,
        vk: &VerifierKey<F, PC>,
    ) -> PC::Commitment {
        //    5 for arithmetic
        // +  2 for permutation
        // +  3 for lookup
        // +  3 for each piece of the quotient poly
        // = 13 length of scalars and points
        let mut scalars = Vec::with_capacity(13);
        let mut points = Vec::with_capacity(13);

        vk.arith.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
        );

        vk.perm.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            alpha,
            beta,
            gamma,
            xi,
            l_1_eval,
            self.z1_commit.clone(),
        );

        vk.lookup.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            alpha,
            delta,
            epsilon,
            l_1_eval,
            self.z2_commit.clone(),
            self.h1_commit.clone(),
        );

        let xi_exp_n_plus_2 = (zh_eval + F::one()) * xi.square();
        let scalar_1 = -zh_eval;
        let scalar_2 = -zh_eval * xi_exp_n_plus_2;
        let scalar_3 = -zh_eval * xi_exp_n_plus_2.square();
        scalars.extend([scalar_1, scalar_2, scalar_3]);
        points.extend([
            self.q_lo_commit.clone(),
            self.q_mid_commit.clone(),
            self.q_hi_commit.clone(),
        ]);

        PC::multi_scalar_mul(&points, &scalars)
    }

    /// Performs the verification of a [`Proof`] returning a boolean result.
    pub(crate) fn verify<T>(
        &self,
        cvk: &PC::VerifierKey,
        vk: &VerifierKey<F, PC>,
        transcript: &mut T,
        pub_inputs: &[F],
    ) -> Result<(), Error>
    where
        T: TranscriptProtocol<F, PC::Commitment>,
    {
        let domain = D::new(vk.n)
            .ok_or(Error::InvalidEvalDomainSize {
                log_size_of_group: vk.n.trailing_zeros(),
                adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
            })?;
        assert_eq!(vk.n, domain.size());

        assert_eq!(
            pub_inputs.len(),
            vk.pi_roots.len(),
            "invalid length of public inputs",
        );

        // Append Public Inputs to the transcript.
        transcript.append_scalars("pi", pub_inputs);

        // Subgroup checks are done when the proof is deserialised.

        // In order for the Verifier and Prover to have the same view in the
        // non-interactive setting Both parties must commit the same
        // elements into the transcript Below the verifier will simulate
        // an interaction with the prover by adding the same elements
        // that the prover added into the transcript, hence generating the
        // same challenges
        //
        // Add commitment to witness polynomials to transcript
        transcript.append_commitment("a_commit", &self.a_commit);
        transcript.append_commitment("b_commit", &self.b_commit);
        transcript.append_commitment("c_commit", &self.c_commit);

        // Add t and h commitment to transcript
        transcript.append_commitment("t_commit", &self.t_commit);
        transcript.append_commitment("h1_commit", &self.h1_commit);
        transcript.append_commitment("h2_commit", &self.h2_commit);

        // Compute permutation challenges and add them to transcript

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

        // Add commitment to permutation polynomial to transcript
        transcript.append_commitment("z1_commit", &self.z1_commit);
        transcript.append_commitment("z2_commit", &self.z2_commit);

        // Compute quotient challenge
        let alpha = transcript.challenge_scalar("alpha");

        // Add commitment to quotient polynomial to transcript
        transcript.append_commitment("q_lo_commit", &self.q_lo_commit);
        transcript.append_commitment("q_mid_commit", &self.q_mid_commit);
        transcript.append_commitment("q_hi_commit", &self.q_hi_commit);

        // Compute evaluation point challenge
        let xi = transcript.challenge_scalar("xi");

        // Compute vanishing polynomial evaluated at `ξ`
        let zh_eval = domain.evaluate_vanishing_polynomial(xi);

        // Compute first lagrange polynomial evaluated at `ξ`
        let l_1_eval = compute_lagrange_evaluation(vk.n, F::one(), zh_eval, xi);

        let r0 = self.compute_r0(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            xi,
            l_1_eval,
            zh_eval,
            pub_inputs,
            vk,
        );

        // Compute linearisation commitment
        let r_commit = self.compute_linearisation_commitment(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            xi,
            l_1_eval,
            zh_eval,
            vk,
        );

        // Add evaluations to transcript
        transcript.append_scalar("a_eval", &self.evaluations.wire_evals.a);
        transcript.append_scalar("b_eval", &self.evaluations.wire_evals.b);
        transcript.append_scalar("c_eval", &self.evaluations.wire_evals.c);

        transcript.append_scalar("sigma1_eval", &self.evaluations.perm_evals.sigma1);
        transcript.append_scalar("sigma2_eval", &self.evaluations.perm_evals.sigma2);
        transcript.append_scalar("z1_next_eval", &self.evaluations.perm_evals.z1_next);

        transcript.append_scalar("q_lookup_eval", &self.evaluations.lookup_evals.q_lookup);
        transcript.append_scalar("t_eval", &self.evaluations.lookup_evals.t);
        transcript.append_scalar("t_next_eval", &self.evaluations.lookup_evals.t_next);
        transcript.append_scalar("z2_next_eval", &self.evaluations.lookup_evals.z2_next);
        transcript.append_scalar("h1_next_eval", &self.evaluations.lookup_evals.h1_next);
        transcript.append_scalar("h2_eval", &self.evaluations.lookup_evals.h2);

        // Commitment Scheme
        // Now we delegate computation to the commitment scheme by batch
        // checking two proofs.
        //
        // The `AggregateProof`, which proves that all the necessary
        // polynomials evaluated at `ξ` are
        // correct and a `Proof` which is proof that the
        // permutation polynomial evaluated at the shifted root of unity is
        // correct

        // Generation of the first aggregated proof: It ensures that the
        // polynomials evaluated at `ξ` are correct.

        // Reconstruct the Aggregated Proof commitments and evals
        // The proof consists of the witness commitment with no blinder

        // Compute aggregate witness to polynomials evaluated at the evaluation challenge `ξ`
        let eta = transcript.challenge_scalar("eta");

        let labeled_r_commit = label_commitment!("r", r_commit);
        let labeled_a_commit = label_commitment!("a", self.a_commit);
        let labeled_b_commit = label_commitment!("b", self.b_commit);
        let labeled_c_commit = label_commitment!("c", self.c_commit);
        let labeled_sigma1_commit = label_commitment!("sigma1", vk.perm.sigma1);
        let labeled_sigma2_commit = label_commitment!("sigma2", vk.perm.sigma2);
        let labeled_q_lookup_commit = label_commitment!("q_lookup", vk.lookup.q_lookup);
        let labeled_t_commit = label_commitment!("t", self.t_commit);
        let labeled_h2_commit = label_commitment!("h2", self.h2_commit);
        
        match PC::check(
            cvk,
            [
                &labeled_r_commit,
                &labeled_a_commit,
                &labeled_b_commit,
                &labeled_c_commit,
                &labeled_sigma1_commit,
                &labeled_sigma2_commit,
                &labeled_q_lookup_commit,
                &labeled_t_commit,
                &labeled_h2_commit,
            ],
            &xi,
            [
                r0,
                self.evaluations.wire_evals.a,
                self.evaluations.wire_evals.b,
                self.evaluations.wire_evals.c,
                self.evaluations.perm_evals.sigma1,
                self.evaluations.perm_evals.sigma2,
                self.evaluations.lookup_evals.q_lookup,
                self.evaluations.lookup_evals.t,
                self.evaluations.lookup_evals.h2,
            ],
            &self.aw_opening,
            eta,
            None,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::ProofVerificationError),
            Err(e) => panic!("{:?}", e),
        }
        .and_then(|_| {
            let labeled_z1_commit = label_commitment!("z1", self.z1_commit);
            let labeled_z2_commit = label_commitment!("z2", self.z2_commit);
            let labeled_h1_commit = label_commitment!("h1", self.h1_commit);

            match PC::check(
                cvk,
                [
                    &labeled_z1_commit,
                    &labeled_z2_commit,
                    &labeled_t_commit,
                    &labeled_h1_commit,
                ],
                &(xi * domain.group_gen()),
                [
                    self.evaluations.perm_evals.z1_next,
                    self.evaluations.lookup_evals.z2_next,
                    self.evaluations.lookup_evals.t_next,
                    self.evaluations.lookup_evals.h1_next,
                ],
                &self.saw_opening,
                eta,
                None,
            ) {
                Ok(true) => Ok(()),
                Ok(false) => Err(Error::ProofVerificationError),
                Err(e) => panic!("{:?}", e),
            }
        })
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::batch_test_kzg;
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;

//     fn test_serde_proof<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//         Proof<F, PC>: std::fmt::Debug + PartialEq,
//     {
//         let proof =
//             crate::constraint_system::helper::gadget_tester::<F, P, PC>(
//                 |_: &mut crate::constraint_system::ConstraintSystem<F, P>| {},
//                 200,
//             )
//             .expect("Empty circuit failed");

//         let mut proof_bytes = vec![];
//         proof.serialize(&mut proof_bytes).unwrap();

//         let obtained_proof =
//             Proof::<F, PC>::deserialize(proof_bytes.as_slice()).unwrap();

//         assert_eq!(proof, obtained_proof);
//     }

//     // Bls12-381 tests
//     batch_test_kzg!(
//         [test_serde_proof],
//         [] => (
//             Bls12_381, ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );
//     // Bls12-377 tests
//     batch_test_kzg!(
//         [test_serde_proof],
//         [] => (
//             Bls12_377, ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
