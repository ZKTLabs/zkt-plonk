// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use std::{marker::PhantomData, rc::Rc};
use ark_ff::{FftField, Field};
use ark_poly::GeneralEvaluationDomain;
use rand_core::{CryptoRng, RngCore};

use crate::{
    commitment::HomomorphicCommitment,
    error::{to_pc_error, Error},
    constraint_system::ConstraintSystem,
    proof_system::{
        Proof,
        ProverKey, ExtendedProverKey, VerifierKey,
        plonkup_setup, plonkup_prove,
    },
    transcript::TranscriptProtocol,
    lookup::LookupTable,
};

/// Trait that should be implemented for any circuit function to provide to it
/// the capabilities of automatically being able to generate, and verify proofs
/// as well as compile the circuit.
///
/// # Example
///
/// ```rust,no_run
/// use ark_bls12_381::{Bls12_381, Fr as BlsScalar};
/// use ark_ec::PairingEngine;
/// use ark_ec::models::twisted_edwards_extended::GroupAffine;
/// use ark_ec::{TEModelParameters, AffineCurve, ProjectiveCurve};
/// use ark_ed_on_bls12_381::{
///     EdwardsAffine as JubJubAffine, EdwardsParameters as JubJubParameters,
///     EdwardsProjective as JubJubProjective, Fr as JubJubScalar,
/// };
/// use ark_ff::{FftField, PrimeField, BigInteger, ToConstraintField};
/// use plonk_core::circuit::{Circuit, verify_proof};
/// use plonk_core::constraint_system::ConstraintSystem;
/// use plonk_core::error::{to_pc_error,Error};
/// use ark_poly::polynomial::univariate::DensePolynomial;
/// use ark_poly_commit::{PolynomialCommitment, sonic_pc::SonicKZG10};
/// use plonk_core::prelude::*;
/// use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
/// use num_traits::{Zero, One};
/// use rand_core::OsRng;
///
/// fn main() -> Result<(), Error> {
/// // Implements a circuit that checks:
/// // 1) a + b = c where C is a PI
/// // 2) a <= 2^6
/// // 3) b <= 2^5
/// // 4) a * b = d where D is a PI
/// // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
/// #[derive(derivative::Derivative)]
///    #[derivative(Debug(bound = ""), Default(bound = ""))]
/// pub struct TestCircuit<F, P>
/// where
///     F: PrimeField,
///     P: TEModelParameters<BaseField = F>,
/// {
///        a: F,
///        b: F,
///        c: F,
///        d: F,
///        e: P::ScalarField,
///        f: GroupAffine<P>,
///    }
///
/// impl<F, P> Circuit<F, P> for TestCircuit<F, P>
/// where
///     F: PrimeField,
///     P: TEModelParameters<BaseField = F>,
///    {
///        const CIRCUIT_ID: [u8; 32] = [0xff; 32];
///
///        fn gadget(
///            &mut self,
///            composer: &mut ConstraintSystem<F, P>,
///        ) -> Result<(), Error> {
///            let a = composer.add_input(self.a);
///            let b = composer.add_input(self.b);
///            let zero = composer.zero_var();
///
///            // Make first constraint a + b = c (as public input)
///            composer.arithmetic_gate(|gate| {
///                gate.witness(a, b, Some(zero))
///                    .add(F::one(), F::one())
///                    .pi(-self.c)
///            });
///
///            // Check that a and b are in range
///            composer.range_gate(a, 1 << 6);
///            composer.range_gate(b, 1 << 5);
///            // Make second constraint a * b = d
///            composer.arithmetic_gate(|gate| {
///                gate.witness(a, b, Some(zero)).mul(F::one()).pi(-self.d)
///            });
///            let e = composer
///                .add_input(from_embedded_curve_scalar::<F, P>(self.e));
///            let (x, y) = P::AFFINE_GENERATOR_COEFFS;
///            let generator = GroupAffine::new(x, y);
///            let scalar_mul_result =
///                composer.fixed_base_scalar_mul(e, generator);
///            // Apply the constrain
///            composer.assert_equal_public_point(scalar_mul_result, self.f);
///            Ok(())
///        }
///
///        fn padded_circuit_size(&self) -> usize {
///            1 << 11
///        }
///    }
///
/// // Generate CRS
/// type PC = SonicKZG10::<Bls12_381,DensePolynomial<BlsScalar>>;
/// let pp = PC::setup(
///     1 << 10, None, &mut OsRng
///  )?;
///
/// let mut circuit = TestCircuit::<BlsScalar, JubJubParameters>::default();
/// // Compile the circuit
/// let (pk_p, (vk, _pi_pos)) = circuit.compile::<PC>(&pp)?;
///
/// let (x, y) = JubJubParameters::AFFINE_GENERATOR_COEFFS;
/// let generator: GroupAffine<JubJubParameters> = GroupAffine::new(x, y);
/// let point_f_pi: GroupAffine<JubJubParameters> = AffineCurve::mul(
///     &generator,
///     JubJubScalar::from(2u64).into_repr(),
/// )
/// .into_affine();
/// // Prover POV
/// let (proof, pi) = {
///     let mut circuit: TestCircuit<BlsScalar, JubJubParameters> = TestCircuit {
///         a: BlsScalar::from(20u64),
///         b: BlsScalar::from(5u64),
///         c: BlsScalar::from(25u64),
///         d: BlsScalar::from(100u64),
///         e: JubJubScalar::from(2u64),
///         f: point_f_pi,
///     };
///     circuit.gen_proof::<PC>(&pp, pk_p, b"Test")
/// }?;
///
/// let verifier_data = VerifierData::new(vk, pi);
/// // Test serialisation for verifier_data
/// let mut verifier_data_bytes = Vec::new();
/// verifier_data.serialize(&mut verifier_data_bytes).unwrap();
///
/// let deserialized_verifier_data: VerifierData<BlsScalar, PC> =
///     VerifierData::deserialize(verifier_data_bytes.as_slice()).unwrap();
///
/// assert!(deserialized_verifier_data == verifier_data);
///
/// // Verifier POV
/// verify_proof::<BlsScalar, JubJubParameters, PC>(
///     &pp,
///     verifier_data.key,
///     &proof,
///     &verifier_data.pi,
///     b"Test",
/// )
/// }
/// ```
pub trait Circuit<F: Field>: Sized {
    ///
    fn register_tables(_: &mut LookupTable<F>) {}
    
    /// Implementation used to fill the composer.
    fn synthesize(self, cs: &mut ConstraintSystem<F>) -> Result<(), Error>;

    ///
    fn circuit(self, cs: &mut ConstraintSystem<F>) -> Result<(), Error> {
        Self::register_tables(&mut cs.lookup_table);
        self.synthesize(cs)
    }
}

///
#[derive(Debug, Default)]
pub struct Plonkup<F, PC, T, C>
where
    F: FftField,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F>,
{
    _f: PhantomData<F>,
    _pc: PhantomData<PC>,
    _t: PhantomData<T>,
    _c: PhantomData<C>,
}

impl<F, PC, T, C> Plonkup<F, PC, T, C>
where
    F: FftField,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F>,
{
    ///
    #[allow(clippy::type_complexity)]
    pub fn compile(
        extend: bool,
        pp: &PC::UniversalParams,
        circuit: C,
    ) -> Result<
        (
            PC::CommitterKey,
            ProverKey<F>,
            Option<ExtendedProverKey<F>>,
            VerifierKey<F, PC>,
        ),
        Error
    > {
        let mut cs = ConstraintSystem::new(true);
        // Generate circuit constraint
        circuit.synthesize(&mut cs)?;

        let (ck, _) = PC::trim(
            pp,
            cs.circuit_bound(),
            0,
            None,
        )
        .map_err(to_pc_error::<F, PC>)?;

        let (pk, epk, vk) =
            plonkup_setup::<_, GeneralEvaluationDomain<_>, _>(&ck, cs, extend)?;

        Ok((ck, pk, epk, vk))
    }

    ///
    pub fn prove<R: CryptoRng + RngCore>(
        ck: &PC::CommitterKey,
        pk: &ProverKey<F>,
        epk: Option<Rc<ExtendedProverKey<F>>>,
        vk: &VerifierKey<F, PC>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<F, GeneralEvaluationDomain<F>, PC>, Error> {
        let mut cs = ConstraintSystem::new(false);
        // Generate circuit constraint
        circuit.synthesize(&mut cs)?;
        
        let transcript = &mut T::new("Plonkup");
        vk.seed_transcript(transcript);

        plonkup_prove(ck, pk, epk, cs, transcript, rng)
    }

    ///
    pub fn verify<'a, I>(
        cvk: &PC::VerifierKey,
        vk: &VerifierKey<F, PC>,
        proof: &Proof<F, GeneralEvaluationDomain<F>, PC>,
        pub_inputs: &[F],
    ) -> Result<(), Error>
    where
        I: IntoIterator<Item = &'a F> + Clone,
    {
        let transcript = &mut T::new("Plonkup");
        vk.seed_transcript(transcript);

        proof.verify_proof(cvk, vk, transcript, pub_inputs)
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{constraint_system::ConstraintSystem, util};
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use ark_ec::{
//         twisted_edwards_extended::GroupAffine, AffineCurve, PairingEngine,
//         ProjectiveCurve,
//     };
//     use ark_ff::{FftField, PrimeField};
//     use rand_core::OsRng;

//     // Implements a circuit that checks:
//     // 1) a + b = c where C is a PI
//     // 2) a <= 2^6
//     // 3) b <= 2^5
//     // 4) a * b = d where D is a PI
//     // 5) JubJub::GENERATOR * e(JubJubScalar) = f where F is a PI
//     #[derive(derivative::Derivative)]
//     #[derivative(Debug(bound = ""), Default(bound = ""))]
//     pub struct TestCircuit<F: FftField, P: TEModelParameters<BaseField = F>> {
//         a: F,
//         b: F,
//         c: F,
//         d: F,
//         e: P::ScalarField,
//         f: GroupAffine<P>,
//     }

//     impl<F, P> Circuit<F, P> for TestCircuit<F, P>
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//     {
//         const CIRCUIT_ID: [u8; 32] = [0xff; 32];

//         fn gadget(
//             &mut self,
//             composer: &mut ConstraintSystem<F, P>,
//         ) -> Result<(), Error> {
//             let a = composer.add_input(self.a);
//             let b = composer.add_input(self.b);
//             let zero = composer.zero_var;

//             // Make first constraint a + b = c (as public input)
//             composer.arithmetic_gate(|gate| {
//                 gate.witness(a, b, Some(zero))
//                     .add(F::one(), F::one())
//                     .pi(-self.c)
//             });

//             // Check that a and b are in range
//             composer.range_gate(a, 1 << 6);
//             composer.range_gate(b, 1 << 5);
//             // Make second constraint a * b = d
//             composer.arithmetic_gate(|gate| {
//                 gate.witness(a, b, Some(zero)).mul(F::one()).pi(-self.d)
//             });
//             let e = composer
//                 .add_input(util::from_embedded_curve_scalar::<F, P>(self.e));
//             let (x, y) = P::AFFINE_GENERATOR_COEFFS;
//             let generator = GroupAffine::new(x, y);
//             let scalar_mul_result =
//                 composer.fixed_base_scalar_mul(e, generator);

//             // Apply the constrain
//             composer.assert_equal_public_point(scalar_mul_result, self.f);
//             Ok(())
//         }

//         fn padded_circuit_size(&self) -> usize {
//             1 << 9
//         }
//     }

//     fn test_full<F, P, PC>() -> Result<(), Error>
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//         VerifierData<F, PC>: PartialEq,
//     {
//         // Generate CRS
//         let pp = PC::setup(1 << 10, None, &mut OsRng)
//             .map_err(to_pc_error::<F, PC>)?;

//         let mut circuit = TestCircuit::<F, P>::default();

//         // Compile the circuit
//         let (pk, (vk, _pi_pos)) = circuit.compile::<PC>(&pp)?;

//         let (x, y) = P::AFFINE_GENERATOR_COEFFS;
//         let generator: GroupAffine<P> = GroupAffine::new(x, y);
//         let point_f_pi: GroupAffine<P> = AffineCurve::mul(
//             &generator,
//             P::ScalarField::from(2u64).into_repr(),
//         )
//         .into_affine();

//         // Prover POV
//         let (proof, pi) = {
//             let mut circuit: TestCircuit<F, P> = TestCircuit {
//                 a: F::from(20u64),
//                 b: F::from(5u64),
//                 c: F::from(25u64),
//                 d: F::from(100u64),
//                 e: P::ScalarField::from(2u64),
//                 f: point_f_pi,
//             };

//             cfg_if::cfg_if! {
//                 if #[cfg(feature = "trace")] {
//                     // Test trace
//                     let mut prover: Prover<F, P, PC> = Prover::new(b"Test");
//                     circuit.gadget(prover.mut_cs())?;
//                     prover.cs.check_circuit_satisfied();
//                 }
//             }

//             circuit.gen_proof::<PC>(&pp, pk, b"Test")?
//         };

//         let verifier_data = VerifierData::new(vk, pi);

//         // Test serialisation for verifier_data
//         let mut verifier_data_bytes = Vec::new();
//         verifier_data.serialize(&mut verifier_data_bytes).unwrap();

//         let deserialized_verifier_data: VerifierData<F, PC> =
//             VerifierData::deserialize(verifier_data_bytes.as_slice()).unwrap();

//         assert!(deserialized_verifier_data == verifier_data);

//         // Verifier POV

//         // TODO: non-ideal hack for a first functional version.
//         assert!(verify_proof::<F, P, PC>(
//             &pp,
//             verifier_data.key,
//             &proof,
//             &verifier_data.pi,
//             b"Test",
//         )
//         .is_ok());

//         Ok(())
//     }

//     #[test]
//     #[allow(non_snake_case)]
//     fn test_full_on_Bls12_381() -> Result<(), Error> {
//         test_full::<
//             <Bls12_381 as PairingEngine>::Fr,
//             ark_ed_on_bls12_381::EdwardsParameters,
//             crate::commitment::KZG10<Bls12_381>,
//         >()
//     }

//     #[test]
//     #[allow(non_snake_case)]
//     fn test_full_on_Bls12_381_ipa() -> Result<(), Error> {
//         test_full::<
//             <Bls12_381 as PairingEngine>::Fr,
//             ark_ed_on_bls12_381::EdwardsParameters,
//             crate::commitment::IPA<
//                 <Bls12_381 as PairingEngine>::G1Affine,
//                 blake2::Blake2b,
//             >,
//         >()
//     }

//     #[test]
//     #[allow(non_snake_case)]
//     fn test_full_on_Bls12_377() -> Result<(), Error> {
//         test_full::<
//             <Bls12_377 as PairingEngine>::Fr,
//             ark_ed_on_bls12_377::EdwardsParameters,
//             crate::commitment::KZG10<Bls12_377>,
//         >()
//     }
//     #[test]
//     #[allow(non_snake_case)]
//     fn test_full_on_Bls12_377_ipa() -> Result<(), Error> {
//         test_full::<
//             <Bls12_377 as PairingEngine>::Fr,
//             ark_ed_on_bls12_377::EdwardsParameters,
//             crate::commitment::IPA<
//                 <Bls12_377 as PairingEngine>::G1Affine,
//                 blake2::Blake2b,
//             >,
//         >()
//     }
// }
