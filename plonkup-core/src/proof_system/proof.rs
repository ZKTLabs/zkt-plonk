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
use ark_ff::FftField;
use ark_poly::EvaluationDomain;
use ark_serialize::{
    Read, Write,
    CanonicalDeserialize, CanonicalSerialize, SerializationError,
};

use crate::{
    label_commitment,
    commitment::HomomorphicCommitment,
    proof_system::{
        linearisation_poly::ProofEvaluations,
        VerifierKey,
    },
    transcript::TranscriptProtocol,
    util::{EvaluationDomainExt, compute_first_lagrange_evaluation},
    error::Error,
};

/// A [`Proof`] is a composition of `Commitment`s to the Witness, Permutation,
/// Quotient, Shifted and Opening polynomials as well as the
/// `ProofEvaluations`.
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

    /// Commitment to the lookup query polynomial.
    pub f_commit: PC::Commitment,

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
        l_1_eval: F,
    ) -> F {
        let alpha_sq = alpha.square();
        let alpha_qu = alpha_sq.square();

        // (a(z) + β*σ1(z) + γ) * (b(z) + β*σ2(z) + γ) * (c(z) + γ) * α * z1(ωz)
        let part_1 = alpha
            * (beta * self.evaluations.perm_evals.sigma1 + self.evaluations.wire_evals.a + gamma)
            * (beta * self.evaluations.perm_evals.sigma2 + self.evaluations.wire_evals.b + gamma)
            * (self.evaluations.wire_evals.c + gamma)
            * self.evaluations.perm_evals.z1_next;

        // L_1(z) * α^2
        let part_2 = l_1_eval * alpha_sq;

        // (ε(1 + δ) + δ * h2(z)) * (ε(1 + δ) + h2(z) + δ * h1(ωz)) * α^4 * z2(ωz)
        let part_3 = {
            let epsilon_one_plus_delta = epsilon * (F::one() + delta);
            alpha_qu
                * self.evaluations.lookup_evals.z2_next
                * (delta * self.evaluations.lookup_evals.h2 + epsilon_one_plus_delta)
                * (delta * self.evaluations.lookup_evals.h1_next
                    + self.evaluations.lookup_evals.h2 + epsilon_one_plus_delta)
        };

        // L_1(z) * α^5
        let part_4 = l_1_eval * alpha_qu * alpha;

        // Return r_0
        part_1 + part_2 + part_3 + part_4
    }

    /// Computes the commitment to `[r]_1`.
    fn compute_linearisation_commitment(
        &self,
        alpha: F,
        beta: F,
        gamma: F,
        delta: F,
        epsilon: F,
        zeta: F,
        z: F,
        l_1_eval: F,
        zh_eval: F,
        pub_inputs: &[F],
        vk: &VerifierKey<F, PC>,
    ) -> PC::Commitment {
        //    5 + public input length for arithmetic
        // +  2 for permutation
        // +  3 for lookup
        // +  3 for each piece of the quotient poly
        // = 13 + public input length of scalars and points
        let mut scalars = Vec::with_capacity(13 + pub_inputs.len());
        let mut points = Vec::with_capacity(13 + pub_inputs.len());

        vk.arith.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            pub_inputs,
        );

        vk.perm.compute_linearisation_commitment(
            &mut scalars,
            &mut points,
            &self.evaluations,
            alpha,
            beta,
            gamma,
            z,
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
            zeta,
            l_1_eval,
            self.z2_commit.clone(),
            self.h1_commit.clone(),
        );

        let z_exp_n_plus_2 = (zh_eval + F::one()) * z.square();
        let scalar_1 = -zh_eval;
        let scalar_2 = -zh_eval * z_exp_n_plus_2;
        let scalar_3 = -zh_eval * z_exp_n_plus_2.square();
        scalars.extend(vec![scalar_1, scalar_2, scalar_3]);
        points.extend(vec![
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
            vk.arith.lagranges.len(),
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

        // Compute table compression challenge `zeta`.
        let zeta = transcript.challenge_scalar("zeta");

        // Add f_poly commitment to transcript
        transcript.append_commitment("f_commit", &self.f_commit);

        // Add h polynomials to transcript
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
        let z = transcript.challenge_scalar("z");

        // Compute zero polynomial evaluated at `z_challenge`
        let zh_eval = domain.evaluate_vanishing_polynomial(z);

        // Compute first lagrange polynomial evaluated at `z_challenge`
        let l_1_eval = compute_first_lagrange_evaluation(vk.n, zh_eval, z);

        let zeta_sq = zeta.square();
        let t_commit = PC::multi_scalar_mul(
            &[
                vk.lookup.t1.clone(),
                vk.lookup.t2.clone(),
                vk.lookup.t3.clone(),
                vk.lookup.t4.clone(),
            ],
            &[F::one(), zeta, zeta_sq, zeta_sq * zeta],
        );

        let r0 = self.compute_r0(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            l_1_eval,
        );

        // Add evaluations to transcript
        transcript.append_scalar("a_eval", &self.evaluations.wire_evals.a);
        transcript.append_scalar("b_eval", &self.evaluations.wire_evals.b);
        transcript.append_scalar("c_eval", &self.evaluations.wire_evals.c);

        transcript.append_scalar("sigma1_eval", &self.evaluations.perm_evals.sigma1);
        transcript.append_scalar("sigma2_eval", &self.evaluations.perm_evals.sigma2);
        transcript.append_scalar("z1_next_eval", &self.evaluations.perm_evals.z1_next);

        transcript.append_scalar("t_tag_eval", &self.evaluations.lookup_evals.t_tag);
        transcript.append_scalar("f_eval", &self.evaluations.lookup_evals.f);
        transcript.append_scalar("t_eval", &self.evaluations.lookup_evals.t);
        transcript.append_scalar("t_next_eval", &self.evaluations.lookup_evals.t_next);
        transcript.append_scalar("z2_next_eval", &self.evaluations.lookup_evals.z2_next);
        transcript.append_scalar("h1_next_eval", &self.evaluations.lookup_evals.h1_next);
        transcript.append_scalar("h2_eval", &self.evaluations.lookup_evals.h2);

        // Compute linearisation commitment
        let linear_commit = self.compute_linearisation_commitment(
            alpha,
            beta,
            gamma,
            delta,
            epsilon,
            zeta,
            z,
            l_1_eval,
            zh_eval,
            pub_inputs,
            vk,
        );

        // Commitment Scheme
        // Now we delegate computation to the commitment scheme by batch
        // checking two proofs.
        //
        // The `AggregateProof`, which proves that all the necessary
        // polynomials evaluated at `z_challenge` are
        // correct and a `Proof` which is proof that the
        // permutation polynomial evaluated at the shifted root of unity is
        // correct

        // Generation of the first aggregated proof: It ensures that the
        // polynomials evaluated at `z_challenge` are correct.

        // Reconstruct the Aggregated Proof commitments and evals
        // The proof consists of the witness commitment with no blinder

        // Compute aggregate witness to polynomials evaluated at the evaluation
        // challenge `z`
        let v = transcript.challenge_scalar("v");

        let aw_commits = [
            label_commitment!(linear_commit),
            label_commitment!(vk.perm.sigma1),
            label_commitment!(vk.perm.sigma2),
            label_commitment!(vk.lookup.t_tag),
            label_commitment!(self.f_commit),
            label_commitment!(self.h2_commit),
            label_commitment!(t_commit),
            label_commitment!(self.a_commit),
            label_commitment!(self.b_commit),
            label_commitment!(self.c_commit),
        ];

        let aw_evals = [
            r0,
            self.evaluations.perm_evals.sigma1,
            self.evaluations.perm_evals.sigma2,
            self.evaluations.lookup_evals.t_tag,
            self.evaluations.lookup_evals.f,
            self.evaluations.lookup_evals.h2,
            self.evaluations.lookup_evals.t,
            self.evaluations.wire_evals.a,
            self.evaluations.wire_evals.b,
            self.evaluations.wire_evals.c,
        ];

        let saw_commits = [
            label_commitment!(self.z1_commit),
            label_commitment!(t_commit),
            label_commitment!(self.z2_commit),
            label_commitment!(self.h1_commit),
        ];

        let saw_evals = [
            self.evaluations.perm_evals.z1_next,
            self.evaluations.lookup_evals.t_next,
            self.evaluations.lookup_evals.z2_next,
            self.evaluations.lookup_evals.h1_next,
        ];

        match PC::check(
            cvk,
            &aw_commits,
            &z,
            aw_evals,
            &self.aw_opening,
            v,
            None,
        ) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::ProofVerificationError),
            Err(e) => panic!("{:?}", e),
        }
        .and_then(|_| {
            match PC::check(
                cvk,
                &saw_commits,
                &(z * domain.group_gen()),
                saw_evals,
                &self.saw_opening,
                v,
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
