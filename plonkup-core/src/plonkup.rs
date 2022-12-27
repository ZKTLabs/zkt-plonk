// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use std::{marker::PhantomData, rc::Rc};
use ark_ff::{FftField, Field};
use ark_poly::EvaluationDomain;
use rand_core::{CryptoRng, RngCore};

use crate::{
    commitment::HomomorphicCommitment,
    error::{to_pc_error, Error},
    constraint_system::ConstraintSystem,
    proof_system::{
        Proof,
        ProverKey, ExtendedProverKey, VerifierKey,
        setup as plonk_setup,
        prove as plonk_prove,
    },
    transcript::TranscriptProtocol,
    util::EvaluationDomainExt,
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
///
pub trait Circuit<F: Field>: Default {    
    /// Implementation used to fill the composer.
    fn synthesize(self, cs: &mut ConstraintSystem<F>) -> Result<(), Error>;
}

///
#[derive(Debug, Default)]
pub struct Plonkup<F, D, PC, T, C>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F>,
{
    _f: PhantomData<F>,
    _d: PhantomData<D>,
    _pc: PhantomData<PC>,
    _t: PhantomData<T>,
    _c: PhantomData<C>,
}

impl<F, D, PC, T, C> Plonkup<F, D, PC, T, C>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F>,
{
    ///
    #[allow(clippy::type_complexity)]
    pub fn compile(
        extend: bool,
        pp: &PC::UniversalParams,
    ) -> Result<
        (
            PC::CommitterKey,
            PC::VerifierKey,
            ProverKey<F>,
            Option<ExtendedProverKey<F>>,
            VerifierKey<F, PC>,
        ),
        Error
    > {
        let mut cs = ConstraintSystem::new(true);
        // Generate circuit constraint
        let circuit = C::default();
        circuit.synthesize(&mut cs)?;

        let (ck, cvk) = PC::trim(
            pp,
            cs.circuit_bound() * 4,
            0,
            None,
        )
        .map_err(to_pc_error::<F, PC>)?;

        let (pk, epk, vk) =
            plonk_setup::<_, D, _>(&ck, cs, extend)?;

        Ok((ck, cvk, pk, epk, vk))
    }

    ///
    pub fn prove<R: CryptoRng + RngCore>(
        ck: &PC::CommitterKey,
        pk: &ProverKey<F>,
        epk: Option<Rc<ExtendedProverKey<F>>>,
        vk: &VerifierKey<F, PC>,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<F, D, PC>, Error> {
        let mut cs = ConstraintSystem::new(false);
        // Generate circuit constraint
        circuit.synthesize(&mut cs)?;
        
        let transcript = &mut T::new("Plonkup");
        vk.seed_transcript(transcript);

        plonk_prove(ck, pk, epk, cs, transcript, rng)
    }

    ///
    pub fn verify(
        cvk: &PC::VerifierKey,
        vk: &VerifierKey<F, PC>,
        proof: &Proof<F, D, PC>,
        pub_inputs: &[F],
    ) -> Result<(), Error> {
        let transcript = &mut T::new("Plonkup");
        vk.seed_transcript(transcript);

        proof.verify(cvk, vk, transcript, pub_inputs)
    }
}

#[cfg(test)]
mod test {
    use ark_ff::PrimeField;
    use ark_poly::GeneralEvaluationDomain;
    use ark_std::test_rng;
    use ark_bn254::Bn254;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;

    use crate::{
        constraint_system::{Variable, Selectors},
        lookup::UintRangeTable,
        transcript::MerlinTranscript,
        batch_test_kzg,
        batch_test_ipa,
    };
    use super::*;

    // Implements a circuit that checks:
    // 1) a + b = c
    // 2) a is in 8 bit range (lookup)
    // 3) b is in 8 bit range (lookup)
    // 4) d = a * c, d is a PI
    #[derive(derivative::Derivative)]
    #[derivative(Debug(bound = ""), Default(bound = ""))]
    pub struct TestCircuit {
        a: u8,
        b: u8,
        c: u8,
        d: u8,
    }

    impl<F: Field> Circuit<F> for TestCircuit {
        fn synthesize(self, cs: &mut ConstraintSystem<F>) -> Result<(), Error> {
            let a = cs.assign_variable(self.a.into());
            let b = cs.assign_variable(self.b.into());

            let c = cs.add_gate(&a.into(), &b.into());

            cs.contains_gate::<UintRangeTable<8>>(a);
            cs.contains_gate::<UintRangeTable<8>>(b);
            
            let sels = Selectors::new_arith()
                .with_mul(-F::one());
            cs.arith_constrain(a, c, Variable::Zero, sels, Some(self.d.into()));

            Ok(())
        }
    }

    type PlonkupInstance<F, PC> = Plonkup<
        F,
        GeneralEvaluationDomain<F>,
        PC,
        MerlinTranscript,
        TestCircuit,
    >;

    fn test_full<F: PrimeField, PC: HomomorphicCommitment<F>>() {
        let rng = &mut test_rng();
        // setup
        let pp =
            PC::setup(1 << 10, None, rng).unwrap();
        let (
            ck,
            cvk,
            pk,
            epk,
            vk,
        ) = PlonkupInstance::<F, PC>::compile(true, &pp).unwrap();

        // prove
        let circuit = TestCircuit {
            a: 2,
            b: 3,
            c: 5,
            d: 10,
        };
        let epk = epk.map(|epk| Rc::new(epk));
        let proof =
            PlonkupInstance::<F, PC>::prove(&ck, &pk, epk, &vk, circuit, rng).unwrap();

        // verify
        PlonkupInstance::<F, PC>::verify(&cvk, &vk, &proof, &[10u8.into()]).unwrap();
    }

    batch_test_kzg!(
        Bn254,
        [test_full],
        []
    );

    batch_test_kzg!(
        Bls12_377,
        [test_full],
        []
    );

    batch_test_kzg!(
        Bls12_381,
        [test_full],
        []
    );

    batch_test_ipa!(
        Bn254,
        [test_full],
        []
    );

    batch_test_ipa!(
        Bls12_377,
        [test_full],
        []
    );

    batch_test_ipa!(
        Bls12_381,
        [test_full],
        []
    );
}
