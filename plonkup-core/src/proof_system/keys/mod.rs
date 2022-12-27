// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.

//! Proof System Widgets

pub mod arithmetic;
pub mod permutation;
pub mod lookup;

use ark_ff::{Field, FftField};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, UVPolynomial};
use ark_serialize::*;

use crate::{
    commitment::HomomorphicCommitment,
    transcript::TranscriptProtocol,
    error::Error,
    util::{compute_lagrange_poly, coset_evals_from_poly, coset_evals_from_poly_ref},
};

/// PLONK circuit Verification Key.
///
/// This structure is used by the Verifier in order to verify a
/// [`Proof`](super::Proof).
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = ""),
    Debug(bound = "arithmetic::VerifierKey<F,PC>: core::fmt::Debug, PC::Commitment: core::fmt::Debug"),
    Eq(bound = "arithmetic::VerifierKey<F,PC>: Eq, PC::Commitment: Eq"),
    PartialEq(bound = "arithmetic::VerifierKey<F,PC>: PartialEq, PC::Commitment: PartialEq"),
)]
pub struct VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Circuit size (padded to a power of two).
    pub n: usize,

    /// Domain roots at Public Inputs indexes
    pub pi_roots: Vec<F>,

    /// Arithmetic Verifier Key
    pub arith: arithmetic::VerifierKey<F, PC>,

    /// VerifierKey for permutation checks
    pub perm: permutation::VerifierKey<PC::Commitment>,

    /// VerifierKey for Lookup Gate
    pub lookup: lookup::VerifierKey<F, PC>,
}

impl<F, PC> VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Constructs a [`VerifierKey`] from the widget VerifierKey's that are
    /// constructed based on the selector polynomial commitments and the
    /// sigma polynomial commitments.
    pub(crate) fn from_polynomial_commitments(
        n: usize,
        pi_roots: Vec<F>,
        q_m: PC::Commitment,
        q_l: PC::Commitment,
        q_r: PC::Commitment,
        q_o: PC::Commitment,
        q_c: PC::Commitment,
        q_lookup: PC::Commitment,
        t_tag: PC::Commitment,
        sigma1: PC::Commitment,
        sigma2: PC::Commitment,
        sigma3: PC::Commitment,
        t1: PC::Commitment,
        t2: PC::Commitment,
        t3: PC::Commitment,
        t4: PC::Commitment,
    ) -> Self {
        assert!(n.is_power_of_two());
        Self {
            n,
            pi_roots,
            arith: arithmetic::VerifierKey {
                q_m,
                q_l,
                q_r,
                q_o,
                q_c,
            },
            perm: permutation::VerifierKey {
                sigma1,
                sigma2,
                sigma3,
            },
            lookup: lookup::VerifierKey {
                q_lookup,
                t_tag,
                t1,
                t2,
                t3,
                t4,
            },
        }
    }
}

impl<F, PC> VerifierKey<F, PC>
where
    F: Field,
    PC: HomomorphicCommitment<F>,
{
    /// Adds the circuit description to the transcript.
    pub(crate) fn seed_transcript<T>(&self, transcript: &mut T)
    where
        T: TranscriptProtocol<F, PC::Commitment>,
    {
        transcript.append_u64("circuit_size", self.n as u64);
        transcript.append_commitment("q_m_commit", &self.arith.q_m);
        transcript.append_commitment("q_l_commit", &self.arith.q_l);
        transcript.append_commitment("q_r_commit", &self.arith.q_r);
        transcript.append_commitment("q_o_commit", &self.arith.q_o);
        transcript.append_commitment("q_c_commit", &self.arith.q_c);
        transcript.append_commitment("sigma1_commit", &self.perm.sigma1);
        transcript.append_commitment("sigma2_commit", &self.perm.sigma2);
        transcript.append_commitment("sigma3_commit", &self.perm.sigma3);
        transcript.append_commitment("q_lookup_commit", &self.lookup.q_lookup);
        transcript.append_commitment("t_tag_commit", &self.lookup.t_tag);
        transcript.append_commitment("t1_commit", &self.lookup.t1);
        transcript.append_commitment("t2_commit", &self.lookup.t2);
        transcript.append_commitment("t3_commit", &self.lookup.t3);
        transcript.append_commitment("t4_commit", &self.lookup.t4);
    }
}

/// PLONK circuit Proving Key.
///
/// This structure is used by the Prover in order to construct a
/// [`Proof`](crate::proof_system::Proof).
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = "lookup::ProverKey<F>: Clone"),
    Debug(bound = "lookup::ProverKey<F>: std::fmt::Debug"),
    Eq(bound = "lookup::ProverKey<F>: Eq"),
    PartialEq(bound = "lookup::ProverKey<F>: PartialEq")
)]
pub struct ProverKey<F: Field> {
    /// Arithmetic Prover Key
    pub arith: arithmetic::ProverKey<F>,

    /// Lookup selector
    pub lookup: lookup::ProverKey<F>,

    /// ProverKey for permutation checks
    pub perm: permutation::ProverKey<F>,
}

impl<F: Field> ProverKey<F> {
    /// Constructs a [`ProverKey`] from the widget ProverKey's that are
    /// constructed based on the selector polynomials and the
    /// sigma polynomials and it's evaluations.
    pub(crate) fn from_polynomials(
        q_m: DensePolynomial<F>,
        q_l: DensePolynomial<F>,
        q_r: DensePolynomial<F>,
        q_o: DensePolynomial<F>,
        q_c: DensePolynomial<F>,
        q_lookup: DensePolynomial<F>,
        t_tag: DensePolynomial<F>,
        sigma1: DensePolynomial<F>,
        sigma2: DensePolynomial<F>,
        sigma3: DensePolynomial<F>,
    ) -> Self {
        Self {
            arith: arithmetic::ProverKey {
                q_m,
                q_l,
                q_r,
                q_o,
                q_c,
            },
            lookup: lookup::ProverKey {
                q_lookup,
                t_tag,
            },
            perm: permutation::ProverKey {
                sigma1,
                sigma2,
                sigma3,
            },
        }
    }

    ///
    pub fn extend_prover_key<D>(
        &self,
        domain: &D,
        sigma1: Vec<F>,
        sigma2: Vec<F>,
        sigma3: Vec<F>,
        q_lookup: Vec<F>,
        t_tag: Vec<F>,
    ) -> Result<ExtendedProverKey<F>, Error>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        let domain_4n = D::new(4 * domain.size())
            .ok_or(Error::InvalidEvalDomainSize {
                log_size_of_group: (4 * domain.size()).trailing_zeros(),
                adicity: <F::FftParams as ark_ff::FftParameters>::TWO_ADICITY,
            })?;

        let q_m_coset = coset_evals_from_poly_ref(&domain_4n, &self.arith.q_m);
        let q_l_coset = coset_evals_from_poly_ref(&domain_4n, &self.arith.q_l);
        let q_r_coset = coset_evals_from_poly_ref(&domain_4n, &self.arith.q_r);
        let q_o_coset = coset_evals_from_poly_ref(&domain_4n, &self.arith.q_o);
        let q_c_coset = coset_evals_from_poly_ref(&domain_4n, &self.arith.q_c);

        let q_lookup_coset = coset_evals_from_poly_ref(&domain_4n, &self.lookup.q_lookup);
        let t_tag_coset = coset_evals_from_poly_ref(&domain_4n, &self.lookup.t_tag);

        let sigma1_coset = coset_evals_from_poly_ref(&domain_4n, &self.perm.sigma1);
        let sigma2_coset = coset_evals_from_poly_ref(&domain_4n, &self.perm.sigma2);
        let sigma3_coset = coset_evals_from_poly_ref(&domain_4n, &self.perm.sigma3);

        let x_coset = coset_evals_from_poly(
            &domain_4n,
            DensePolynomial::from_coefficients_vec(vec![F::zero(), F::one()]),
        );

        // Compute 4n evaluations for x^n - 1
        let vh_poly: DensePolynomial<_> = domain.vanishing_polynomial().into();
        let vh_coset = coset_evals_from_poly(&domain_4n, vh_poly);

        let l_1_poly = compute_lagrange_poly(domain, 0);
        let l_1_coset = coset_evals_from_poly(&domain_4n, l_1_poly);

        Ok(ExtendedProverKey {
            arith: arithmetic::ExtendedProverKey {
                q_m_coset,
                q_l_coset,
                q_r_coset,
                q_o_coset,
                q_c_coset,
            },
            lookup: lookup::ExtendedProverKey {
                q_lookup,
                q_lookup_coset,
                t_tag,
                t_tag_coset,
            },
            perm: permutation::ExtendedProverKey {
                sigma1,
                sigma1_coset,
                sigma2,
                sigma2_coset,
                sigma3,
                sigma3_coset,
                x_coset,
            },
            vh_coset,
            l_1_coset,
        })
    }
}

/// PLONK circuit Extended Proving Key.
///
/// This structure is used by the Prover in order to construct a
/// [`Proof`](crate::proof_system::Proof).
#[derive(CanonicalDeserialize, CanonicalSerialize, derivative::Derivative)]
#[derivative(
    Clone(bound = "lookup::ExtendedProverKey<F>: Clone"),
    Debug(bound = "lookup::ExtendedProverKey<F>: std::fmt::Debug"),
    Eq(bound = "lookup::ExtendedProverKey<F>: Eq"),
    PartialEq(bound = "lookup::ExtendedProverKey<F>: PartialEq")
)]
pub struct ExtendedProverKey<F: FftField> {
    /// Arithmetic Prover Key
    pub arith: arithmetic::ExtendedProverKey<F>,

    /// Lookup selector
    pub lookup: lookup::ExtendedProverKey<F>,

    /// ProverKey for permutation checks
    pub perm: permutation::ExtendedProverKey<F>,

    /// Pre-processes the 4n Evaluations for the vanishing polynomial, so
    /// they do not need to be computed at the proving stage.
    ///
    /// NOTE: With this, we can combine all parts of the quotient polynomial
    /// in their evaluation phase and divide by the quotient
    /// polynomial without having to perform IFFT
    pub vh_coset: Vec<F>,

    ///
    pub l_1_coset: Vec<F>,
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::batch_test;
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use ark_ec::models::TEModelParameters;
//     use ark_poly::polynomial::univariate::DensePolynomial;
//     use ark_poly::{EvaluationDomain, GeneralEvaluationDomain, UVPolynomial};
//     use rand_core::OsRng;

//     fn rand_poly_eval<F>(n: usize) -> (DensePolynomial<F>, Evaluations<F>)
//     where
//         F: PrimeField,
//     {
//         let polynomial = DensePolynomial::rand(n, &mut OsRng);
//         (polynomial, rand_evaluations(n))
//     }

//     fn rand_evaluations<F>(n: usize) -> Evaluations<F>
//     where
//         F: PrimeField,
//     {
//         let domain = GeneralEvaluationDomain::new(4 * n).unwrap();
//         let values: Vec<_> = (0..8 * n).map(|_| F::rand(&mut OsRng)).collect();
//         Evaluations::from_vec_and_domain(values, domain)
//     }

//     fn rand_multiset<F>(n: usize) -> MultiSet<F>
//     where
//         F: PrimeField,
//     {
//         let mut rng = OsRng;
//         core::iter::from_fn(|| Some(F::rand(&mut rng)))
//             .take(n)
//             .collect()
//     }

//     #[test]
//     fn test_serialise_deserialise_prover_key() {
//         type F = ark_bls12_381::Fr;
//         let n = 1 << 11;

//         let q_m = rand_poly_eval(n);
//         let q_l = rand_poly_eval(n);
//         let q_r = rand_poly_eval(n);
//         let q_o = rand_poly_eval(n);
//         let q_4 = rand_poly_eval(n);
//         let q_c = rand_poly_eval(n);
//         let q_arith = rand_poly_eval(n);
//         let q_range = rand_poly_eval(n);
//         let q_logic = rand_poly_eval(n);
//         let q_lookup = rand_poly_eval(n);
//         let q_fixed_group_add = rand_poly_eval(n);
//         let q_variable_group_add = rand_poly_eval(n);

//         let left_sigma = rand_poly_eval(n);
//         let right_sigma = rand_poly_eval(n);
//         let out_sigma = rand_poly_eval(n);
//         let fourth_sigma = rand_poly_eval(n);

//         let linear_evaluations = rand_evaluations(n);
//         let v_h_coset_8n = rand_evaluations(n);
//         let table_1 = rand_multiset(n);
//         let table_2 = rand_multiset(n);
//         let table_3 = rand_multiset(n);
//         let table_4 = rand_multiset(n);

//         let prover_key = ProverKey::from_polynomials_and_evals(
//             n,
//             q_m,
//             q_l,
//             q_r,
//             q_o,
//             q_4,
//             q_c,
//             q_arith,
//             q_range,
//             q_logic,
//             q_lookup,
//             q_fixed_group_add,
//             q_variable_group_add,
//             left_sigma,
//             right_sigma,
//             out_sigma,
//             fourth_sigma,
//             linear_evaluations,
//             v_h_coset_8n,
//             table_1,
//             table_2,
//             table_3,
//             table_4,
//         );

//         let mut prover_key_bytes = vec![];
//         prover_key
//             .serialize_unchecked(&mut prover_key_bytes)
//             .unwrap();

//         let obtained_pk: ProverKey<F> =
//             ProverKey::deserialize_unchecked(prover_key_bytes.as_slice())
//                 .unwrap();

//         assert_eq!(prover_key, obtained_pk);
//     }

//     fn test_serialise_deserialise_verifier_key<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//         VerifierKey<F, PC>: PartialEq,
//     {
//         let n = 2usize.pow(5);

//         let q_m = PC::Commitment::default();
//         let q_l = PC::Commitment::default();
//         let q_r = PC::Commitment::default();
//         let q_o = PC::Commitment::default();
//         let q_4 = PC::Commitment::default();
//         let q_c = PC::Commitment::default();
//         let q_arith = PC::Commitment::default();
//         let q_range = PC::Commitment::default();
//         let q_logic = PC::Commitment::default();
//         let q_lookup = PC::Commitment::default();
//         let q_fixed_group_add = PC::Commitment::default();
//         let q_variable_group_add = PC::Commitment::default();

//         let left_sigma = PC::Commitment::default();
//         let right_sigma = PC::Commitment::default();
//         let out_sigma = PC::Commitment::default();
//         let fourth_sigma = PC::Commitment::default();

//         let table_1 = PC::Commitment::default();
//         let table_2 = PC::Commitment::default();
//         let table_3 = PC::Commitment::default();
//         let table_4 = PC::Commitment::default();

//         let verifier_key = VerifierKey::<F, PC>::from_polynomial_commitments(
//             n,
//             q_m,
//             q_l,
//             q_r,
//             q_o,
//             q_4,
//             q_c,
//             q_arith,
//             q_range,
//             q_logic,
//             q_lookup,
//             q_fixed_group_add,
//             q_variable_group_add,
//             left_sigma,
//             right_sigma,
//             out_sigma,
//             fourth_sigma,
//             table_1,
//             table_2,
//             table_3,
//             table_4,
//         );

//         let mut verifier_key_bytes = vec![];
//         verifier_key
//             .serialize_unchecked(&mut verifier_key_bytes)
//             .unwrap();

//         let obtained_vk: VerifierKey<F, PC> =
//             VerifierKey::deserialize_unchecked(verifier_key_bytes.as_slice())
//                 .unwrap();

//         assert!(verifier_key == obtained_vk);
//     }

//     // Test for Bls12_381
//     batch_test!(
//         [test_serialise_deserialise_verifier_key],
//         [] => (
//             Bls12_381, ark_ed_on_bls12_381::EdwardsParameters      )
//     );

//     // Test for Bls12_377
//     batch_test!(
//         [test_serialise_deserialise_verifier_key],
//         [] => (
//             Bls12_377, ark_ed_on_bls12_377::EdwardsParameters       )
//     );
// }
