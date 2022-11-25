// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Methods to preprocess the constraint system for use in a proof.

use ark_ff::{FftField, Field};
use ark_poly::EvaluationDomain;

use crate::{
    commitment::HomomorphicCommitment,
    constraint_system::{ConstraintSystem, SetupComposer},
    error::{to_pc_error, Error},
    label_polynomial,
    proof_system::{ProverKey, ExtendedProverKey, VerifierKey},
    util::{compute_lagrange_poly, poly_from_evals, poly_from_evals_ref},
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
    }
}

///
pub(crate) fn plonkup_setup<F, D, PC>(
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

    let mut composer = cs.composer.unwrap_setup();
    // Pad composer
    composer.pad_to(n);

    let mut label_polynomials = Vec::with_capacity(13 + composer.pp.size());

    let q_m_poly = poly_from_evals(&domain, composer.q_m);
    let q_l_poly = poly_from_evals(&domain, composer.q_l);
    let q_r_poly = poly_from_evals(&domain, composer.q_r);
    let q_o_poly = poly_from_evals(&domain, composer.q_o);
    let q_c_poly = poly_from_evals(&domain, composer.q_c);
    let q_lookup_poly = poly_from_evals_ref(&domain, &composer.q_lookup);

    label_polynomials.push(label_polynomial!(q_m_poly));
    label_polynomials.push(label_polynomial!(q_l_poly));
    label_polynomials.push(label_polynomial!(q_r_poly));
    label_polynomials.push(label_polynomial!(q_o_poly));
    label_polynomials.push(label_polynomial!(q_c_poly));
    label_polynomials.push(label_polynomial!(q_lookup_poly));

    // 2. Compute the sigma polynomials
    let (sigma1_evals, sigma2_evals, sigma3_evals) =
        composer.perm.compute_all_sigma_evals(n, &domain);

    let sigma1_poly = poly_from_evals_ref(&domain, &sigma1_evals);
    let sigma2_poly = poly_from_evals_ref(&domain, &sigma2_evals);
    let sigma3_poly = poly_from_evals_ref(&domain, &sigma3_evals);

    label_polynomials.push(label_polynomial!(sigma1_poly));
    label_polynomials.push(label_polynomial!(sigma2_poly));
    label_polynomials.push(label_polynomial!(sigma3_poly));

    // 3. Compute lookup table polynomials
    let mut t_polys = cs.lookup_table.to_polynomials(&domain);
    let t4_poly = t_polys.pop().unwrap();
    let t3_poly = t_polys.pop().unwrap();
    let t2_poly = t_polys.pop().unwrap();
    let t1_poly = t_polys.pop().unwrap();

    label_polynomials.push(label_polynomial!(t1_poly));
    label_polynomials.push(label_polynomial!(t2_poly));
    label_polynomials.push(label_polynomial!(t3_poly));
    label_polynomials.push(label_polynomial!(t4_poly));

    // 4. Compute Lagrange polynomials at public indexes
    for index in composer.pp.get_pos() {
        let poly = ark_poly_commit::LabeledPolynomial::new(
            format!("lagrange_{}_poly", index + 1),
            compute_lagrange_poly(&domain, *index),
            None,
            None,
        );
        label_polynomials.push(poly);
    }

    let (label_commitments, _) = PC::commit(
        ck,
        &label_polynomials,
        None,
    )
    .map_err(to_pc_error::<F, PC>)?;

    let lagranges = label_commitments[13..]
        .iter()
        .map(|lc| lc.commitment().clone())
        .collect();
    let vk = VerifierKey::from_polynomial_commitments(
        n,
        label_commitments[0].commitment().clone(), // q_m
        label_commitments[1].commitment().clone(), // q_l
        label_commitments[2].commitment().clone(), // q_r
        label_commitments[3].commitment().clone(), // q_o
        label_commitments[4].commitment().clone(), // q_c
        label_commitments[5].commitment().clone(), // q_lookup
        label_commitments[6].commitment().clone(), // sigma1
        label_commitments[7].commitment().clone(), // sigma2
        label_commitments[8].commitment().clone(), // sigma3
        label_commitments[9].commitment().clone(), // t1
        label_commitments[10].commitment().clone(), // t2
        label_commitments[11].commitment().clone(), // t3
        label_commitments[12].commitment().clone(), // t4
        lagranges,
    );

    let mut polys_iter = label_polynomials
        .into_iter()
        .map(|lp| lp.polynomial().clone());

    let pk = ProverKey::from_polynomials(
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
        polys_iter.next().unwrap(),
    );

    let epk = if extend {
        let mut polys_iter = polys_iter.skip(3);
        let t4 = polys_iter.next().unwrap();
        let lagranges = polys_iter.collect();
        let epk = pk.extend_prover_key(
            &domain,
            sigma1_evals,
            sigma2_evals,
            sigma3_evals,
            composer.q_lookup,
            t4,
            lagranges,
        )?;
        Some(epk)
    } else {
        None
    };

    Ok((pk, epk, vk))
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{batch_test_field_params, constraint_system::helper::*};
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;

//     /// Tests that the circuit gets padded to the correct length.
//     // FIXME: We can do this test without dummy_gadget method.
//     fn test_pad<F, P>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//     {
//         let mut composer: ConstraintSystem<F, P> = ConstraintSystem::new();
//         dummy_gadget(100, &mut composer);

//         // Pad the circuit to next power of two
//         let next_pow_2 = composer.n.next_power_of_two() as u64;
//         composer.pad(next_pow_2 as usize - composer.n);

//         let size = composer.n;
//         assert!(size.is_power_of_two());
//         assert_eq!(composer.q_m.len(), size);
//         assert_eq!(composer.q_l.len(), size);
//         assert_eq!(composer.q_o.len(), size);
//         assert_eq!(composer.q_r.len(), size);
//         assert_eq!(composer.q_c.len(), size);
//         assert_eq!(composer.q_arith.len(), size);
//         assert_eq!(composer.q_range.len(), size);
//         assert_eq!(composer.q_logic.len(), size);
//         assert_eq!(composer.q_lookup.len(), size);
//         assert_eq!(composer.q_fixed_group_add.len(), size);
//         assert_eq!(composer.q_variable_group_add.len(), size);
//         assert_eq!(composer.w_l.len(), size);
//         assert_eq!(composer.w_r.len(), size);
//         assert_eq!(composer.w_o.len(), size);
//     }

//     // Bls12-381 tests
//     batch_test_field_params!(
//         [test_pad],
//         [] => (
//             Bls12_381,
//             ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Bls12-377 tests
//     batch_test_field_params!(
//         [test_pad],
//         [] => (
//             Bls12_377,
//             ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
