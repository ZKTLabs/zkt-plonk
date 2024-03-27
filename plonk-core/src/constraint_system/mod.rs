// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! The constraint system module stores the implementation of the PLONK
//! [`ConstraintSystem`], as well as the circuit tools and abstractions, used by
//! the Composer to generate, build, preprocess circuits.

mod arithmetic;
mod boolean;
mod composer;
mod variable;
mod pi;
mod helper;

pub use boolean::*;
pub use composer::*;
pub use variable::*;
pub use helper::*;
pub use pi::*;

use ark_ff::Field;
use itertools::Itertools;

use crate::lookup::LookupTable;

/// The ConstraintSystem is the circuit-builder tool that the `plonk` repository
/// provides to create, stored and transformed circuit descriptions
/// into a [`Proof`](crate::proof_system::Proof) at some point.
///
/// A ConstraintSystem stores the fullcircuit information, being this one
/// all of the witness and circuit descriptors info (values, positions in the
/// circuits, gates and Wires that occupy..), the public inputs, the connection
/// relationships between the witnesses and how they're repesented as Wires (so
/// basically the Permutation argument etc..).
///
/// The ConstraintSystem also grants us a way to introduce our secret
/// witnesses in the form of a [`Variable`] into the circuit description as well
/// as the public inputs. We can do this with methods like
/// [`ConstraintSystem::add_input`].
///
/// The ConstraintSystem also contains as associated functions all the
/// neccessary tools to be able to instrument the circuits that the user needs
/// through the addition of gates. There are functions that may add a single
/// arithmetic gate to the circuit [`ConstraintSystem::arithmetic_gate`] and
/// others that can add several gates to the circuit description such as
/// [`ConstraintSystem::conditional_select`].
///
/// Each gate or group of gates adds a specific functionallity or operation to
/// the circuit description, and so, that's why we can understand
/// the ConstraintSystem as a builder.
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct ConstraintSystem<F: Field, const TABLE_SIZE: usize> {
    ///
    pub composer: Composer<F>,
    ///
    pub lookup_table: LookupTable<F, TABLE_SIZE>,
}

impl<F: Field, const TABLE_SIZE: usize> ConstraintSystem<F, TABLE_SIZE> {
    ///
    pub fn new(setup: bool, lookup_table: LookupTable<F, TABLE_SIZE>) -> Self {
        let composer = if setup {
            Composer::Setup(SetupComposer::new())
        } else {
            Composer::Proving(ProvingComposer::new())
        };

        Self { composer, lookup_table }
    }

    ///
    pub fn with_capacity(
        setup: bool,
        constraint_size: usize,
        variable_size: usize,
        lookup_table: LookupTable<F, TABLE_SIZE>,
    ) -> Self {
        let composer = if setup {
            Composer::Setup(
                SetupComposer::with_capacity(constraint_size, variable_size)
            )
        } else {
            Composer::Proving(
                ProvingComposer::with_capacity(constraint_size, variable_size)
            )
        };

        Self { composer, lookup_table }
    }

    /// Returns the length of the circuit that can accomodate the lookup table.
    fn total_size(&self) -> usize {
        core::cmp::max(self.composer.size(), TABLE_SIZE)
    }

    /// Returns the smallest power of two needed for the curcuit.
    pub fn circuit_bound(&self) -> usize {
        self.total_size().next_power_of_two()
    }

    ///
    pub fn assign_variable(&mut self, value: F) -> Variable {
        match &mut self.composer {
            Composer::Setup(composer) => {
                composer.perm.new_variable()
            }
            Composer::Proving(composer) => {
                composer.var_map.assign_variable(value)
            }
        }
    }

    ///
    pub fn arith_constrain(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        sels: Selectors<F>,
        pi: Option<F>,
    ) {
        match &mut self.composer {
            Composer::Setup(composer) => {
                composer.gate_constrain(w_l, w_r, w_o, sels, pi.is_some());
            }
            Composer::Proving(composer) => {
                composer.input_wires(w_l, w_r, w_o, pi);
            }
        }
    }
}

impl<F: Field, const TABLE_SIZE: usize> ConstraintSystem<F, TABLE_SIZE> {

    /// Constrain a value in the lookup table.
    pub fn lookup_constrain(&mut self, x: &LTVariable<F>) {
        match &mut self.composer {
            Composer::Setup(composer) => {
                let w_o = composer.perm.new_variable();
                let sels = Selectors::new()
                    .with_left(F::one())
                    .with_out(-F::one())
                    .with_lookup()
                    .by_left_lt(x);
                composer.gate_constrain(x.var, Variable::Zero, w_o, sels, false);
            }
            Composer::Proving(composer) => {
                let out = composer.var_map.value_of_lt_var(x);
                let w_o = composer.var_map.assign_variable(out);
                composer.input_wires(x.var, Variable::Zero, w_o, None);
            }
        }
    }

    /// Add a constraint into the circuit description that states that two
    /// [`Variable`]s are equal.
    pub fn equal_constrain(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) {
        let sels = Selectors::new()
            .with_left(F::one())
            .with_right(-F::one())
            .by_left_lt(x)
            .by_right_lt(y);
        
        self.arith_constrain(x.var, y.var, Variable::Zero, sels, None);
    }

    ///
    pub fn bits_le_constrain(&mut self, bits: &[Boolean]) -> Variable {
        // We restrict the length of the bits to be a power of two, so that we
        // can use a recursive construction.
        assert!(bits.len().is_power_of_two(), "bits length must be a power of two");

        let mut vars = bits.iter().map(|bit| bit.0).collect_vec();
        let mut multiplier = 2u64;
        while vars.len() > 1 {
            vars = vars
                .chunks(2)
                .map(|chunk| {
                    match &mut self.composer {
                        Composer::Setup(composer) => {
                            let new_var = composer.perm.new_variable();
                            let sels = Selectors::new()
                                .with_left(F::one())
                                .with_right(F::from(multiplier))
                                .with_out(-F::one());

                            composer.gate_constrain(chunk[0], chunk[1], new_var, sels, false);

                            new_var
                        }
                        Composer::Proving(composer) => {
                            let left = composer.var_map.value_of_var(chunk[0]);
                            let right = composer.var_map.value_of_var(chunk[1]);
                            let new_val = left + right * F::from(multiplier);
                            let new_var = composer.var_map.assign_variable(new_val);

                            composer.input_wires(chunk[0], chunk[1], new_var, None);

                            new_var
                        }
                    }
                })
                .collect_vec();
            multiplier *= multiplier;
        }

        vars[0]
    }

    /// x = public input
    pub fn set_variable_public(&mut self, x: &LTVariable<F>) {
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_out(-F::one())
                    .by_out_lt(x);

                composer.gate_constrain(
                    Variable::Zero,
                    Variable::Zero,
                    x.var,
                    sels,
                    true,
                );
            }
            Composer::Proving(composer) => {
                composer.input_wires(
                    Variable::Zero,
                    Variable::Zero,
                    x.var,
                    Some(composer.var_map.value_of_lt_var(x)),
                );
            }
        }
    }

    /// A gate which outputs a variable whose value is 1 if
    /// the input is 0 and whose value is 0 otherwise
    pub fn should_be_zero_with_output(&mut self, x: &LTVariable<F>) -> Boolean {
        // Enforce constraints. The constraint system being used here is
        // x * y + z - 1 = 0
        // x * z = 0
        // where y is auxiliary and z is the boolean (x == 0).
        let (y, z): (Variable, Variable);
        match &mut self.composer {
            Composer::Setup(composer) => {
                y = composer.perm.new_variable();
                z = composer.perm.new_variable();

                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_out(F::one())
                    .with_constant(-F::one())
                    .by_out_lt(x);

                composer.gate_constrain(x.var, y, z, sels, false);

                let sels = Selectors::new()
                    .with_mul(F::one())
                    .by_out_lt(x);

                composer.gate_constrain(x.var, z, Variable::Zero, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = x_value.inverse().unwrap_or_default();
                let z_value = if x_value.is_zero() { F::one() } else { F::zero() };

                y = composer.var_map.assign_variable(y_value);
                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x.var, y, z, None);
                composer.input_wires(x.var, z, Variable::Zero, None);
            }
        }

        Boolean(z)
    }

    /// A gate which outputs a variable whose value is 1 if the
    /// two input variables have equal values and whose value is 0 otherwise.
    pub fn should_eq_with_output(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) -> Boolean {
        let difference = self.sub_gate(x, y);
        self.should_be_zero_with_output(&difference.into())
    }

    /// Conditionally selects a [`Variable`] based on an input bit.
    ///
    /// If:
    /// bit == 1 => choice_a,
    /// bit == 0 => choice_b,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`ConstraintSystem::boolean_gate`].
    pub fn conditional_select(
        &mut self,
        bit: Boolean,
        choice_a: &LTVariable<F>,
        choice_b: &LTVariable<F>,
    ) -> Variable {
        let (x, y, z): (Variable, Variable, Variable);
        // bit * a - x = 0
        // (1 - bit) * b - y = 0 => b - bit * b - y = 0
        // x + y - z = 0
        match &mut self.composer {
            Composer::Setup(composer) => {
                x = composer.perm.new_variable();
                y = composer.perm.new_variable();
                z = composer.perm.new_variable();

                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_out(-F::one())
                    .by_right_lt(choice_a);

                composer.gate_constrain(bit.0, choice_a.var, x, sels, false);

                let sels = Selectors::new()
                    .with_mul(-F::one())
                    .with_right(F::one())
                    .with_out(-F::one())
                    .by_right_lt(choice_b);

                composer.gate_constrain(bit.0, choice_b.var, y, sels, false);

                let sels = Selectors::new()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one());
                
                composer.gate_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit.0);
                assert!(bit_value.is_one() || bit_value.is_zero());
                let x_value = composer.var_map.value_of_lt_var(choice_a);
                let y_value = composer.var_map.value_of_lt_var(choice_b);
                let x_value = bit_value * x_value;
                let y_value = (F::one() - bit_value) * y_value;
                let z_value = x_value + y_value;

                x = composer.var_map.assign_variable(x_value);
                y = composer.var_map.assign_variable(y_value);
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(bit.0, choice_a.var, x, None);
                composer.input_wires(bit.0, choice_b.var, y, None);
                composer.input_wires(x, y, z, None);
            }
        }

        z
    }

    /// Adds the polynomial f(x) = x * a to the circuit description where
    /// `x = bit`. If:
    /// bit == 1 => value,
    /// bit == 0 => 0,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should have previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`ConstraintSystem::boolean_gate`].
    pub fn conditional_select_zero(
        &mut self,
        bit: Boolean,
        value: &LTVariable<F>,
    ) -> Variable {
        // bit * value - out = 0
        let out: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                out = composer.perm.new_variable();

                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_out(-F::one())
                    .by_right_lt(value);

                composer.gate_constrain(bit.0, value.var, out, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit.0);
                assert!(bit_value.is_one() || bit_value.is_zero());
                let out_value = if bit_value.is_zero() {
                    F::zero()
                } else {
                    composer.var_map.value_of_lt_var(value)
                };

                out = composer.var_map.assign_variable(out_value);
                
                composer.input_wires(bit.0, value.var, out, None);
            }
        }

        out
    }

    /// Adds the polynomial f(x) = 1 - x + xa to the circuit description where
    /// `x = bit`. If:
    /// bit == 1 => value,
    /// bit == 0 => 1,
    ///
    /// # Note
    /// The `bit` used as input which is a [`Variable`] should had previously
    /// been constrained to be either 1 or 0 using a bool constrain. See:
    /// [`ConstraintSystem::boolean_gate`].
    pub fn conditional_select_one(
        &mut self,
        bit: Boolean,
        value: &LTVariable<F>,
    ) -> Variable {
        // bit * value - bit - out + 1 = 0
        let out: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                out = composer.perm.new_variable();

                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_left(-F::one())
                    .with_out(-F::one())
                    .with_constant(F::one())
                    .by_right_lt(value);

                composer.gate_constrain(bit.0, value.var, out, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit.0);
                assert!(bit_value.is_one() || bit_value.is_zero());
        
                let out_value = if bit_value.is_zero() {
                    F::one()
                } else {
                    composer.var_map.value_of_lt_var(value)
                };

                out = composer.var_map.assign_variable(out_value);

                composer.input_wires(bit.0, value.var, out, None)
            }
        }

        out
    }
}

#[cfg(test)]
mod test {
    use ark_ff::Field;
    use ark_std::test_rng;
    use ark_bn254::Bn254;

    use crate::{batch_test_field, lookup::LookupTable};
    use super::{ConstraintSystem, test_gate_constraints};

    fn test_set_variable_public<F: Field>() {
        let rng = &mut test_rng();
        let pi = F::rand(rng);
        test_gate_constraints(
            |cs: &mut ConstraintSystem<_, 0>| -> Vec<_> {
                let x = cs.assign_variable(pi);
                cs.set_variable_public(&x.into());

                vec![]
            },
            &[pi],
            LookupTable::default(),
        )
    }

    batch_test_field!(
        Bn254,
        [
            test_set_variable_public
        ],
        []
    );
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{
//         batch_test, batch_test_field_params,
//         commitment::HomomorphicCommitment,
//         constraint_system::helper::*,
//         proof_system::{Prover, Verifier},
//     };
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use rand_core::OsRng;

//     /// Tests that a circuit initially has 3 gates.
//     fn test_initial_circuit_size<F, P>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//     {
//         // NOTE: Circuit size is n+4 because
//         // - We have an extra gate which forces the first witness to be zero.
//         //   This is used when the advice wire is not being used.
//         // - We have two gates which add random values to blind the wires.
//         // - Another gate which adds 2 pairs of equal points to blind the
//         //   permutation polynomial
//         assert_eq!(4, ConstraintSystem::<F, P>::new().n)
//     }

//     /// Tests that an empty circuit proof passes.
//     fn test_prove_verify<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         // NOTE: Does nothing except add the dummy constraints.
//         let res =
//             gadget_tester::<F, P, PC>(|_: &mut ConstraintSystem<F, P>| {}, 200);
//         assert!(res.is_ok());
//     }

//     fn test_correct_is_zero_with_output<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         // Check that it gives true on zero input:
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let one = composer.add_input(F::one());
//                 let is_zero = composer.is_zero_with_output(composer.zero_var());
//                 composer.assert_equal(is_zero, one);
//             },
//             32,
//         );

//         // Check that it gives false on non-zero input:
//         let res2 = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let one = composer.add_input(F::one());
//                 let is_zero = composer.is_zero_with_output(one);
//                 composer.assert_equal(is_zero, composer.zero_var());
//             },
//             32,
//         );

//         assert!(res.is_ok() && res2.is_ok())
//     }

//     fn test_correct_is_eq_with_output<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         // Check that it gives true on equal inputs:
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let one = composer.add_input(F::one());

//                 let field_element = F::one().double();
//                 let a = composer.add_input(field_element);
//                 let b = composer.add_input(field_element);
//                 let is_eq = composer.is_eq_with_output(a, b);
//                 composer.assert_equal(is_eq, one);
//             },
//             32,
//         );

//         // Check that it gives false on non-equal inputs:
//         let res2 = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let field_element = F::one().double();
//                 let a = composer.add_input(field_element);
//                 let b = composer.add_input(field_element.double());
//                 let is_eq = composer.is_eq_with_output(a, b);
//                 composer.assert_equal(is_eq, composer.zero_var());
//             },
//             32,
//         );

//         assert!(res.is_ok() && res2.is_ok())
//     }

//     fn test_conditional_select<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let bit_1 = composer.add_input(F::one());
//                 let bit_0 = composer.zero_var();

//                 let choice_a = composer.add_input(F::from(10u64));
//                 let choice_b = composer.add_input(F::from(20u64));

//                 let choice =
//                     composer.conditional_select(bit_1, choice_a, choice_b);
//                 composer.assert_equal(choice, choice_a);

//                 let choice =
//                     composer.conditional_select(bit_0, choice_a, choice_b);
//                 composer.assert_equal(choice, choice_b);
//             },
//             32,
//         );
//         assert!(res.is_ok(), "{:?}", res.err().unwrap());
//     }

//     // FIXME: Move this to integration tests
//     fn test_multiple_proofs<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let u_params = PC::setup(2 * 30, None, &mut OsRng).unwrap();

//         // Create a prover struct
//         let mut prover: Prover<F, P, PC> = Prover::new(b"demo");

//         // Add gadgets
//         dummy_gadget(10, prover.mut_cs());

//         // Commit Key
//         let (ck, vk) = PC::trim(&u_params, 2 * 20, 0, None).unwrap();

//         // Preprocess circuit
//         prover.preprocess(&ck).unwrap();

//         let public_inputs = prover.cs.get_pi().clone();

//         let mut proofs = Vec::new();

//         // Compute multiple proofs
//         for _ in 0..3 {
//             proofs.push(prover.prove(&ck).unwrap());

//             // Add another witness instance
//             dummy_gadget(10, prover.mut_cs());
//         }

//         // Verifier
//         //
//         let mut verifier = Verifier::<F, P, PC>::new(b"demo");

//         // Add gadgets
//         dummy_gadget(10, verifier.mut_cs());

//         // Preprocess
//         verifier.preprocess(&ck).unwrap();

//         for proof in proofs {
//             assert!(verifier.verify(&proof, &vk, &public_inputs).is_ok());
//         }
//     }

//     // Tests for Bls12_381
//     batch_test_field_params!(
//         [
//             test_initial_circuit_size
//         ],
//         [] => (
//             Bls12_381,
//             ark_ed_on_bls12_381::EdwardsParameters

//         )
//     );

//     // Tests for Bls12_377
//     batch_test_field_params!(
//         [
//             test_initial_circuit_size
//         ],
//         [] => (
//             Bls12_377,
//             ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );

//     // Tests for Bls12_381
//     batch_test!(
//         [
//             test_prove_verify,
//             test_correct_is_zero_with_output,
//             test_correct_is_eq_with_output,
//             test_conditional_select,
//             test_multiple_proofs
//         ],
//         [] => (
//             Bls12_381,
//             ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Tests for Bls12_377
//     batch_test!(
//         [
//             test_prove_verify,
//             test_correct_is_zero_with_output,
//             test_correct_is_eq_with_output,
//             test_conditional_select,
//             test_multiple_proofs
//         ],
//         [] => (
//             Bls12_377,
//             ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
