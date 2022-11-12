// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

// use crate::{
//     commitment::HomomorphicCommitment,
//     error::{to_pc_error, Error},
//     proof_system::{Prover, Verifier},
// };
// use ark_ec::ModelParameters;
// use ark_ff::PrimeField;
// use rand_core::OsRng;

// use super::{ConstraintSystem, gate::Gate};

// /// Takes a generic gadget function with no auxillary input and tests whether it
// /// passes an end-to-end test.
// #[allow(dead_code)]
// pub(crate) fn gadget_tester<F, P, PC>(
//     gadget: fn(&mut ConstraintSystem<F, P>),
//     n: usize,
// ) -> Result<crate::proof_system::Proof<F, PC>, Error>
// where
//     F: PrimeField,
//     P: ModelParameters<BaseField = F>,
//     PC: HomomorphicCommitment<F>,
// {
//     // Common View
//     let universal_params =
//         PC::setup(2 * n, None, &mut OsRng).map_err(to_pc_error::<F, PC>)?;

//     // Provers View
//     let (proof, public_inputs) = {
//         // Create a prover struct
//         let mut prover = Prover::<F, P, PC>::new(b"demo");

//         // Additionally key the transcript
//         prover.key_transcript(b"key", b"additional seed information");

//         // Add gadgets
//         gadget(prover.mut_cs());

//         // Commit Key
//         let (ck, _) =
//             PC::trim(&universal_params, prover.circuit_bound(), 0, None)
//                 .map_err(to_pc_error::<F, PC>)?;

//         // Preprocess circuit
//         prover.preprocess(&ck)?;

//         // Once the prove method is called, the public inputs are cleared
//         // So pre-fetch these before calling Prove
//         let public_inputs = prover.cs.get_pi().clone();

//         // Compute Proof
//         (prover.prove(&ck)?, public_inputs)
//     };
//     // Verifiers view
//     //
//     // Create a Verifier object
//     let mut verifier = Verifier::new(b"demo");

//     // Additionally key the transcript
//     verifier.key_transcript(b"key", b"additional seed information");

//     // Add gadgets
//     gadget(verifier.mut_cs());

//     // Compute Commit and Verifier Key
//     let (ck, vk) =
//         PC::trim(&universal_params, verifier.circuit_bound(), 0, None)
//             .map_err(to_pc_error::<F, PC>)?;

//     // Preprocess circuit
//     verifier.preprocess(&ck)?;

//     // Verify proof
//     verifier.verify(&proof, &vk, &public_inputs)?;
//     Ok(proof)
// }

use ark_ff::Field;

use super::{ConstraintSystem, composer::check_arith_gate};

///
pub(super) fn test_arith_gates<F, Fn>(mut process: Fn)
where
    F: Field,
    Fn: FnMut(&mut ConstraintSystem<F>),
{
    let mut setup = ConstraintSystem::new(true);
    let mut proving = ConstraintSystem::new(false);

    process(&mut setup);
    process(&mut proving);

    check_arith_gate(
        setup.composer.setup_ref(),
        proving.composer.proving_ref(),
    );
}