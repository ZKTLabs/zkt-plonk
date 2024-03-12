//! Correct, Naive, reference implementation of Poseidon hash function.

use alloc::rc::Rc;
use ark_ff::PrimeField;
use core::{fmt::Debug, marker::PhantomData};
use derivative::Derivative;
use plonk_core::{constraint_system::{ConstraintSystem, LTVariable}, error::Error};

use crate::hasher::FieldHasher;
use super::{PoseidonError, constants::PoseidonConstants};

pub trait PoseidonRefSpec<CS, const WIDTH: usize> {
    /// Field used as state
    type Field: Debug + Clone;

    type ParameterField: PrimeField;

    fn full_round(
        cs: &mut CS,
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        let pre_round_keys = constants
            .round_constants
            .iter()
            .skip(*constants_offset)
            .map(Some);

        state.iter_mut().zip(pre_round_keys).for_each(|(l, pre)| {
            *l = Self::quintic_s_box(cs, l.clone(), pre.copied(), None);
        });

        *constants_offset += WIDTH;

        Self::product_mds(cs, constants, state);
    }

    fn partial_round(
        cs: &mut CS,
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
        state: &mut [Self::Field; WIDTH],
    ) {
        // TODO: we can combine add_round_constants and s_box using fewer
        // constraints
        Self::add_round_constants(cs, state, constants, constants_offset);

        // apply quintic s-box to the first element
        state[0] = Self::quintic_s_box(cs, state[0].clone(), None, None);

        // Multiply by MDS
        Self::product_mds(cs, constants, state);
    }

    fn add_round_constants(
        cs: &mut CS,
        state: &mut [Self::Field; WIDTH],
        constants: &PoseidonConstants<Self::ParameterField>,
        constants_offset: &mut usize,
    ) {
        for (element, round_constant) in state
            .iter_mut()
            .zip(constants.round_constants.iter().skip(*constants_offset))
        {
            // element.com_add_constant(c, round_constant);
            *element = Self::add_constant(cs, element, round_constant)
        }

        *constants_offset += WIDTH;
    }

    fn product_mds(
        cs: &mut CS,
        constants: &PoseidonConstants<Self::ParameterField>,
        state: &mut [Self::Field; WIDTH],
    ) {
        let matrix = &constants.mds_matrices.m;
        let mut result = Self::zeros::<WIDTH>();
        for (j, val) in result.iter_mut().enumerate() {
            for (i, row) in matrix.iter_rows().enumerate() {
                // *val += row[j] * state[i];
                let tmp = Self::mul_constant(cs, &state[i], &row[j]);
                *val = Self::add(cs, val, &tmp);
            }
        }
        *state = result;
    }

    /// return (x + pre_add)^5 + post_add
    fn quintic_s_box(
        cs: &mut CS,
        x: Self::Field,
        pre_add: Option<Self::ParameterField>,
        post_add: Option<Self::ParameterField>,
    ) -> Self::Field {
        let mut tmp = match pre_add {
            Some(a) => Self::add_constant(cs, &x, &a),
            None => x.clone(),
        };
        tmp = Self::power_of_5(cs, &tmp);
        match post_add {
            Some(a) => Self::add_constant(cs, &tmp, &a),
            None => tmp,
        }
    }

    fn power_of_5(cs: &mut CS, x: &Self::Field) -> Self::Field {
        let mut tmp = Self::mul(cs, x, x); // x^2
        tmp = Self::mul(cs, &tmp, &tmp); // x^4
        Self::mul(cs, &tmp, x) // x^5
    }

    fn constant(v: Self::ParameterField) -> Self::Field;

    fn zeros<const W: usize>() -> [Self::Field; W];

    fn zero() -> Self::Field {
        Self::zeros::<1>()[0].clone()
    }

    fn add(cs: &mut CS, x: &Self::Field, y: &Self::Field) -> Self::Field;

    fn add_constant(
        cs: &mut CS,
        a: &Self::Field,
        b: &Self::ParameterField,
    ) -> Self::Field;

    fn mul(cs: &mut CS, x: &Self::Field, y: &Self::Field) -> Self::Field;

    fn mul_constant(
        cs: &mut CS,
        x: &Self::Field,
        y: &Self::ParameterField,
    ) -> Self::Field;
}

pub struct NativePlonkSpecRef<F: PrimeField> {
    _field: PhantomData<F>,
}

impl<F: PrimeField, const WIDTH: usize> PoseidonRefSpec<(), WIDTH> for NativePlonkSpecRef<F> {
    type Field = F;
    type ParameterField = F;

    fn constant(v: Self::ParameterField) -> Self::Field {
        v
    }

    fn zeros<const W: usize>() -> [Self::Field; W] {
        [F::zero(); W]
    }

    fn add(_cs: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x + *y
    }

    fn add_constant(_cs: &mut (), a: &Self::Field, b: &Self::ParameterField) -> Self::Field {
        *a + *b
    }

    fn mul(_cs: &mut (), x: &Self::Field, y: &Self::Field) -> Self::Field {
        *x * *y
    }

    fn mul_constant(_cs: &mut (), x: &Self::Field, y: &Self::ParameterField) -> Self::Field {
        *x * *y
    }
}

pub struct PlonkSpecRef;

impl<F: PrimeField, const WIDTH: usize>
    PoseidonRefSpec<ConstraintSystem<F>, WIDTH> for PlonkSpecRef
{
    type Field = LTVariable<F>;
    type ParameterField = F;

    fn constant(v: Self::ParameterField) -> Self::Field {
        LTVariable::constant(v)
    }

    fn zeros<const W: usize>() -> [Self::Field; W] {
        [LTVariable::zero(); W]
    }

    fn add(
        cs: &mut ConstraintSystem<F>,
        x: &Self::Field,
        y: &Self::Field,
    ) -> Self::Field {
        cs.add_gate(x, y).into()
    }

    fn add_constant(
        _cs: &mut ConstraintSystem<F>,
        x: &Self::Field,
        y: &Self::ParameterField,
    ) -> Self::Field {
        x.linear_transform(F::one(), *y)
    }

    fn mul(
        cs: &mut ConstraintSystem<F>,
        x: &Self::Field,
        y: &Self::Field,
    ) -> Self::Field {
        cs.mul_gate(x, y).into()
    }

    fn mul_constant(
        _cs: &mut ConstraintSystem<F>,
        x: &Self::Field,
        y: &Self::ParameterField,
    ) -> Self::Field {
        x.linear_transform(*y, F::zero())
    }
}

#[derive(Derivative)]
#[derivative(Debug(bound = ""))]
pub struct PoseidonRef<CS, S, const WIDTH: usize>
where
    S: PoseidonRefSpec<CS, WIDTH> + ?Sized,
{
    pub(crate) constants_offset: usize,
    pub(crate) current_round: usize,
    pub elements: [S::Field; WIDTH],
    pos: usize,
    pub(crate) constants: Rc<PoseidonConstants<S::ParameterField>>,
}

impl<
    CS,
    S: PoseidonRefSpec<CS, WIDTH>,
    const WIDTH: usize,
> PoseidonRef<CS, S, WIDTH> {

    fn reset(&mut self) {
        self.constants_offset = 0;
        self.current_round = 0;
        self.elements[1..].iter_mut().for_each(|l| *l = S::zero());
        self.elements[0] = S::constant(self.constants.domain_tag);
        self.pos = 1;
    }

    /// input one field element to Poseidon. Return the position of the element
    /// in state.
    fn input(&mut self, input: S::Field) -> Result<usize, PoseidonError> {
        // Cannot input more elements than the defined constant width
        if self.pos >= WIDTH {
            return Err(PoseidonError::FullBuffer);
        }

        // Set current element, and increase the pointer
        self.elements[self.pos] = input;
        self.pos += 1;

        Ok(self.pos - 1)
    }

    /// Output the hash
    fn output_hash(&mut self, cs: &mut CS) -> S::Field {
        S::full_round(
            cs,
            &self.constants,
            &mut self.constants_offset,
            &mut self.elements,
        );

        for _ in 1..self.constants.half_full_rounds {
            S::full_round(
                cs,
                &self.constants,
                &mut self.constants_offset,
                &mut self.elements,
            );
        }

        S::partial_round(
            cs,
            &self.constants,
            &mut self.constants_offset,
            &mut self.elements,
        );

        for _ in 1..self.constants.partial_rounds {
            S::partial_round(
                cs,
                &self.constants,
                &mut self.constants_offset,
                &mut self.elements,
            );
        }

        for _ in 0..self.constants.half_full_rounds {
            S::full_round(
                cs,
                &self.constants,
                &mut self.constants_offset,
                &mut self.elements,
            )
        }

        self.elements[1].clone()
    }
}

impl<
    CS,
    S: PoseidonRefSpec<CS, WIDTH>,
    const WIDTH: usize,
> Default for PoseidonRef<CS, S, WIDTH> {
    fn default() -> Self {
        let param = Rc::new(PoseidonConstants::generate::<WIDTH>());
        PoseidonRef::new(&param)
    }
}

impl<
    CS,
    S: PoseidonRefSpec<CS, WIDTH>,
    const WIDTH: usize,
> FieldHasher<CS, S::Field> for PoseidonRef<CS, S, WIDTH> {

    type Params = Rc<PoseidonConstants<S::ParameterField>>;

    fn new(constants: &Self::Params) -> Self {
        let mut elements = S::zeros();
        elements[0] = S::constant(constants.domain_tag);
        PoseidonRef {
            constants_offset: 0,
            current_round: 0,
            elements,
            pos: 1,
            constants: constants.clone(),
        }
    }

    fn empty_hash() -> S::Field {
        S::zero()
    }

    fn hash(&mut self, cs: &mut CS, input: &[S::Field]) -> Result<S::Field, Error> {
        self.reset();
        for element in input {
            self.input(element.clone()).map_err(|e| Error::SynthesisError {
                error: format!("Poseidon Error: {:?}", e),
            })?;
        }
        Ok(self.output_hash(cs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::PairingEngine;
    use plonk_core::constraint_system::test_gate_constraints;

    type E = ark_bls12_381::Bls12_381;
    type Fr = <E as PairingEngine>::Fr;
    use ark_std::{test_rng, UniformRand};

    #[test]
    // poseidon should output something if num_inputs = arity
    fn sanity_test() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;

        test_gate_constraints(
            |cs| {
                let rng = &mut test_rng();

                // native poseidon
                let param = Rc::new(PoseidonConstants::generate::<WIDTH>());
                let mut poseidon =
                    PoseidonRef::<(), NativePlonkSpecRef<Fr>, WIDTH>::new(&param);
                let inputs = (0..ARITY).map(|_| Fr::rand(rng)).collect::<Vec<_>>();
                inputs.iter().for_each(|x| {
                    let _ = poseidon.input(*x).unwrap();
                });
                let native_hash = poseidon.output_hash(&mut ());

                // poseidon circuit
                let inputs_var =
                    inputs.iter().map(|x| cs.assign_variable(*x)).collect::<Vec<_>>();
                let mut poseidon =
                    PoseidonRef::<ConstraintSystem<Fr>, PlonkSpecRef, WIDTH>::new(&param);
                inputs_var.into_iter().for_each(|x| {
                    let _ = poseidon.input(x.into()).unwrap();
                });
                let plonk_hash = poseidon.output_hash(cs);
    
                [(plonk_hash, native_hash)]
            },
            &[],
        );
    }

    #[test]
    #[should_panic]
    // poseidon should output something if num_inputs > arity
    fn sanity_test_failure() {
        const ARITY: usize = 4;
        const WIDTH: usize = ARITY + 1;
        let mut rng = test_rng();

        let param = Rc::new(PoseidonConstants::generate::<WIDTH>());
        let mut poseidon =
            PoseidonRef::<(), NativePlonkSpecRef<Fr>, WIDTH>::new(&param);
        (0..(ARITY + 1)).for_each(|_| {
            let _ = poseidon.input(Fr::rand(&mut rng)).unwrap();
        });
        let _ = poseidon.output_hash(&mut ());
    }
}
