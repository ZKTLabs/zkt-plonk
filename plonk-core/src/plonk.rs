// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Tools & traits for PLONK circuits

use core::marker::PhantomData;
use alloc::rc::Rc;
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
    util::EvaluationDomainExt, lookup::LookupTable,
};

/// Trait that should be implemented for any circuit function to provide to it
/// the capabilities of automatically being able to generate, and verify proofs
/// as well as compile the circuit.
pub trait Circuit<F: Field, const TABLE_SIZE: usize>: Default {
    /// Implementation used to fill the composer.
    fn synthesize(self, cs: &mut ConstraintSystem<F, TABLE_SIZE>) -> Result<(), Error>;
}

///
#[derive(Debug, Default)]
pub struct ZKTPlonk<F, D, PC, T, C, const TABLE_SIZE: usize>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F, TABLE_SIZE>,
{
    _f: PhantomData<F>,
    _d: PhantomData<D>,
    _pc: PhantomData<PC>,
    _t: PhantomData<T>,
    _c: PhantomData<C>,
}

impl<F, D, PC, T, C, const TABLE_SIZE: usize> ZKTPlonk<F, D, PC, T, C, TABLE_SIZE>
where
    F: FftField,
    D: EvaluationDomain<F> + EvaluationDomainExt<F>,
    PC: HomomorphicCommitment<F>,
    T: TranscriptProtocol<F, PC::Commitment>,
    C: Circuit<F, TABLE_SIZE>,
{
    ///
    #[allow(clippy::type_complexity)]
    pub fn compile(extend: bool, pp: &PC::UniversalParams) -> Result<
        (
            PC::CommitterKey,
            PC::VerifierKey,
            ProverKey<F>,
            Option<ExtendedProverKey<F>>,
            VerifierKey<F, PC>,
        ),
        Error
    > {
        let mut cs = ConstraintSystem::new(true, LookupTable::default());
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
            plonk_setup::<_, D, _, TABLE_SIZE>(&ck, cs, extend)?;

        Ok((ck, cvk, pk, epk, vk))
    }

    ///
    pub fn prove<I: Into<LookupTable<F, TABLE_SIZE>>, R: CryptoRng + RngCore>(
        ck: &PC::CommitterKey,
        pk: &ProverKey<F>,
        epk: Option<Rc<ExtendedProverKey<F>>>,
        vk: &VerifierKey<F, PC>,
        table: I,
        circuit: C,
        rng: &mut R,
    ) -> Result<Proof<F, D, PC>, Error> {
        let mut cs = ConstraintSystem::new(false, table.into());
        // Generate circuit constraint
        circuit.synthesize(&mut cs)?;

        let transcript = &mut T::new("ZKT Plonk");
        vk.seed_transcript(transcript);

        plonk_prove(ck, pk, epk, vk, cs, transcript, rng)
    }

    ///
    pub fn verify(
        cvk: &PC::VerifierKey,
        vk: &VerifierKey<F, PC>,
        proof: &Proof<F, D, PC>,
        pub_inputs: &[F],
    ) -> Result<(), Error> {
        let transcript = &mut T::new("ZKT Plonk");
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
        transcript::MerlinTranscript,
        batch_test_kzg,
        batch_test_ipa,
    };
    use super::*;

    const SIZE: usize = 100;

    // Implements a circuit that checks:
    // 1) a + b = c
    // 2) d = a * c, d is a PI
    // 3) if (e) { f = a } else { f = b }, f is a PI
    // 4) c exists in table
    #[derive(derivative::Derivative, Default)]
    #[derivative(Debug(bound = ""))]
    pub struct TestCircuit {
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: bool,
    }

    impl<F: Field> Circuit<F, SIZE> for TestCircuit {
        fn synthesize(self, cs: &mut ConstraintSystem<F, SIZE>) -> Result<(), Error> {
            let a = cs.assign_variable(self.a.into());
            let b = cs.assign_variable(self.b.into());
            
            let c = cs.add_gate(&a.into(), &b.into());
            let sels = Selectors::new()
                .with_mul(-F::one());
            cs.arith_constrain(a, c, Variable::Zero, sels, Some(self.d.into()));

            let e = cs.assign_variable(self.e.into());
            let e = cs.boolean_gate(e);
            let f = cs.conditional_select(e, &a.into(), &b.into());
            cs.set_variable_public(&f.into());
            
            cs.lookup_constrain(&c.into());
            
            Ok(())
        }
    }

    type ZKTPlonkInstance<F, PC> = ZKTPlonk<
        F,
        GeneralEvaluationDomain<F>,
        PC,
        MerlinTranscript,
        TestCircuit,
        SIZE,
    >;

    fn test_full<F: PrimeField, PC: HomomorphicCommitment<F>>() {
        let rng = &mut test_rng();
        // setup
        let pp =
            PC::setup(1 << 10, None, rng)
                .unwrap_or_else(|e| panic!("setup failed: {e}"));
        let (ck, cvk, pk, epk, vk) =
            ZKTPlonkInstance::<F, PC>::compile(true, &pp)
                .unwrap_or_else(|e| panic!("compile failed: {e}"));

        // prove
        let circuit = TestCircuit {
            a: 2,
            b: 3,
            c: 5,
            d: 10,
            e: true,
        };
        let epk = epk.map(Rc::new);
        let table = [F::from(1u64), F::from(2u64), F::from(5u64)];
        let proof =
            ZKTPlonkInstance::<F, PC>::prove(&ck, &pk, epk, &vk, table, circuit, rng)
                .unwrap_or_else(|e| panic!("prove failed: {e}"));

        // verify
        ZKTPlonkInstance::<F, PC>::verify(&cvk, &vk, &proof, &[10u64.into(), 2u64.into()])
            .unwrap_or_else(|e| panic!("verify failed: {e}"));
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
