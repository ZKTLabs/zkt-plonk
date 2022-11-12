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
mod lookup;
mod composer;
mod variable;

pub(crate) mod helper;

pub(crate) use composer::{Composer, SetupComposer, ProvingComposer};
pub use variable::{Variable, VariableMap};
pub use arithmetic::ArithSelectors;

use ark_ff::Field;

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
pub struct ConstraintSystem<F: Field> {
    ///
    pub composer: Composer<F>,
    ///
    pub(crate) lookup_table: LookupTable<F>,
}

impl<F: Field> ConstraintSystem<F> {
    ///
    pub fn new(setup: bool) -> Self {
        let composer = if setup {
            Composer::Setup(SetupComposer::new())
        } else {
            Composer::Proving(ProvingComposer::new())
        };

        Self {
            composer,
            lookup_table: LookupTable::new(),
        }
    }

    ///
    pub fn new_with_capacity(
        setup: bool,
        constraint_size: usize,
        variable_size: usize,
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

        Self {
            composer,
            lookup_table: LookupTable::new(),
        }
    }

    /// Returns the length of the circuit that can accomodate the lookup table.
    fn total_size(&self) -> usize {
        let circuit_size = match &self.composer {
            Composer::Setup(composer) => composer.n,
            Composer::Proving(composer) => composer.n,
        };
        std::cmp::max(circuit_size, self.lookup_table.size())
    }

    /// Returns the smallest power of two needed for the curcuit.
    pub fn circuit_bound(&self) -> usize {
        self.total_size().next_power_of_two()
    }

    ///
    pub fn assign_variable(&mut self, value: F) -> Variable {
        match &mut self.composer {
            Composer::Setup(composer) => composer.perm.new_variable(),
            Composer::Proving(composer) => {
                composer.var_map.assign_variable(value)
            }
        }
    }

    /// Add a constraint into the circuit description that states that two
    /// [`Variable`]s are equal.
    pub fn constrain_equal(&mut self, x: Variable, y: Variable) {
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_left(F::one())
                    .with_right(-F::one());

                composer.arith_constrain(
                    x,
                    y,
                    Variable(None),
                    sels,
                    false,
                );
            }
            Composer::Proving(composer) => {
                composer.input_wires(
                    x,
                    y,
                    Variable(None),
                    None,
                );
            }
        }
    }

    /// Constrain a [`Variable`] to be equal to
    /// a specific constant value which is part of the circuit description and
    /// **NOT** a Public Input. ie. this value will be the same for all of the
    /// circuit instances and [`Proof`](crate::proof_system::Proof)s generated.
    pub fn constrain_variable(&mut self, x: Variable, constant: F, pi: Option<F>) {
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_out(F::one())
                    .with_constant(-constant);

                composer.arith_constrain(
                    Variable(None),
                    Variable(None),
                    x,
                    sels,
                    pi.is_some(),
                );
            }
            Composer::Proving(composer) => {
                composer.input_wires(
                    Variable(None),
                    Variable(None),
                    x,
                    pi,
                );
            }
        }
    }

    // ///
    // pub fn set_var_to_pi(&mut self, a: Variable, constant: F) {
    //     match &mut self.composer {
    //         Composer::SetupComposer(composer) => {
    //             let sels = ArithSelectors::default()
    //                 .with_out(-F::one())
    //                 .with_constant(-constant);

    //             composer.arith_constrain(
    //                 Variable(None),
    //                 Variable(None),
    //                 a,
    //                 sels,
    //                 true,
    //             );
    //         }
    //         Composer::ProvingComposer(mode) => {
    //             let pi = mode.var_map.value_of_var(a);
    //             mode.input_wires(
    //                 Variable(None),
    //                 Variable(None),
    //                 a,
    //                 Some(pi),
    //             );
    //         }
    //     }
    // }

    /// A gate which outputs a variable whose value is 1 if
    /// the input is 0 and whose value is 0 otherwise
    pub fn is_zero_with_output(&mut self, x: Variable) -> Variable {
        // Enforce constraints. The constraint system being used here is
        // x * y + z - 1 = 0
        // x * z = 0
        // where b is auxiliary and b is the boolean (x == 0).
        let (y, z): (Variable, Variable);

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(F::one())
                    .with_constant(-F::one());

                y = composer.perm.new_variable();
                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);

                let sels = ArithSelectors::default()
                    .with_mul(F::one());

                composer.arith_constrain(x, z, Variable(None), sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = x_value.inverse().unwrap_or_default();
                let z_value = if x_value.is_zero() { F::one() } else { F::zero() };

                y = composer.var_map.assign_variable(y_value);
                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x, y, z, None);
                composer.input_wires(x, z, Variable(None), None);
            }
        }

        z
    }

    /// A gate which outputs a variable whose value is 1 if the
    /// two input variables have equal values and whose value is 0 otherwise.
    pub fn is_eq_with_output(&mut self, x: Variable, y: Variable) -> Variable {
        let difference = self.sub_gate(x, y);
        self.is_zero_with_output(difference)
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
        bit: Variable,
        choice_a: Variable,
        choice_b: Variable,
    ) -> Variable {
        let (x, y, z): (Variable, Variable, Variable);
        
        // bit * a - x = 0
        // (1 - bit) * b - y = 0 => b - bit * b - y = 0
        // x + y - z = 0
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(-F::one());

                x = composer.perm.new_variable();

                composer.arith_constrain(bit, choice_a, x, sels, false);

                let sels = ArithSelectors::default()
                    .with_mul(-F::one())
                    .with_right(F::one())
                    .with_out(-F::one());

                y = composer.perm.new_variable();

                composer.arith_constrain(bit, choice_b, y, sels, false);

                let sels = ArithSelectors::default()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit);
                assert!(bit_value.is_one() || bit_value.is_zero());
        
                let x_value = composer.var_map.value_of_var(choice_a);
                let y_value = composer.var_map.value_of_var(choice_b);
                let x_value = bit_value * x_value;
                let y_value = (F::one() - bit_value) * y_value;
                let z_value = x_value + y_value;

                composer.var_map.assign_variable(x_value);
                composer.var_map.assign_variable(y_value);
                z = composer.var_map.assign_variable(z_value);
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
        bit: Variable,
        value: Variable,
    ) -> Variable {
        let out: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                // bit * value - out = 0
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(-F::one());

                out = composer.perm.new_variable();

                composer.arith_constrain(bit, value, out, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit);
                assert!(bit_value.is_one() || bit_value.is_zero());

                let out_value = if bit_value.is_zero() {
                    F::zero()
                } else {
                    composer.var_map.value_of_var(value)
                };

                out = composer.var_map.assign_variable(out_value);
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
        bit: Variable,
        value: Variable,
    ) -> Variable {
        let out: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                // bit * value - bit - out + 1 = 0
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_left(-F::one())
                    .with_out(-F::one())
                    .with_constant(F::one());

                out = composer.perm.new_variable();

                composer.arith_constrain(bit, value, out, sels, false);
            }
            Composer::Proving(composer) => {
                let bit_value = composer.var_map.value_of_var(bit);
                assert!(bit_value.is_one() || bit_value.is_zero());
        
                let out_value = if bit_value.is_zero() {
                    F::one()
                } else {
                    composer.var_map.value_of_var(value)
                };

                out = composer.var_map.assign_variable(out_value);
            }
        }

        out
    }

    // /// This function adds two dummy gates to the circuit
    // /// description which are guaranteed to always satisfy the gate equation.
    // /// This function is only used in benchmarking
    // pub fn add_dummy_constraints(&mut self) {
    //     let var_six = self.add_input(F::from(6u64));
    //     let var_one = self.add_input(F::one());
    //     let var_seven = self.add_input(F::from(7u64));
    //     let var_min_twenty = self.add_input(-F::from(20u64));

    //     self.q_m.push(F::from(1u64));
    //     self.q_l.push(F::from(2u64));
    //     self.q_r.push(F::from(3u64));
    //     self.q_o.push(F::from(4u64));
    //     self.q_c.push(F::from(4u64));
    //     self.q_lookup.push(F::one());
    //     self.w_l.push(var_six);
    //     self.w_r.push(var_seven);
    //     self.w_o.push(var_min_twenty);
    //     self.perm.add_variables_to_map(
    //         var_six,
    //         var_seven,
    //         var_min_twenty,
    //         self.n,
    //     );
    //     self.n += 1;

    //     self.q_m.push(F::one());
    //     self.q_l.push(F::one());
    //     self.q_r.push(F::one());
    //     self.q_o.push(F::one());
    //     self.q_c.push(F::from(127u64));
    //     self.q_lookup.push(F::one());
    //     self.w_l.push(var_min_twenty);
    //     self.w_r.push(var_six);
    //     self.w_o.push(var_seven);
    //     self.perm.add_variables_to_map(
    //         var_min_twenty,
    //         var_six,
    //         var_seven,
    //         self.n,
    //     );
    //     self.n += 1;
    // }

    /// Utility function that checks on the "front-end"
    /// side of the PLONK implementation if the identity polynomial
    /// is satisfied for each of the [`ConstraintSystem`]'s gates.
    ///
    /// The recommended usage is to derive the std output and the std error to a
    /// text file and analyze the gates there.
    ///
    /// # Panic
    /// The function by itself will print each circuit gate info until one of
    /// the gates does not satisfy the equation or there are no more gates. If
    /// the cause is an unsatisfied gate equation, the function will panic.
    #[cfg(feature = "trace")]
    pub fn check_circuit_satisfied(&mut self) {
        let w_l: Vec<&F> = self
            .w_l
            .iter()
            .map(|w_l_i| self.var_map.get(w_l_i).unwrap())
            .collect();
        let w_r: Vec<&F> = self
            .w_r
            .iter()
            .map(|w_r_i| self.var_map.get(w_r_i).unwrap())
            .collect();
        let w_o: Vec<&F> = self
            .w_o
            .iter()
            .map(|w_o_i| self.var_map.get(w_o_i).unwrap())
            .collect();
        let pi_vec = self.public_inputs.as_evals(self.circuit_bound());

        for i in 0..self.n {
            let qm = self.q_m[i];
            let ql = self.q_l[i];
            let qr = self.q_r[i];
            let qo = self.q_o[i];
            let qc = self.q_c[i];
            let qarith = self.q_arith[i];
            let pi = pi_vec[i];

            let a = w_l[i];
            let a_next = w_l[(i + 1) % self.n];
            let b = w_r[i];
            let b_next = w_r[(i + 1) % self.n];
            let c = w_o[i];

            #[cfg(all(feature = "trace-print"))]
            std::println!(
                "--------------------------------------------\n
            #Gate Index = {}
            #Selector Polynomials:\n
            - qm -> {:?}\n
            - ql -> {:?}\n
            - qr -> {:?}\n
            - qo -> {:?}\n
            - qc -> {:?}\n
            - q_arith -> {:?}\n
            # Witness polynomials:\n
            - w_l -> {:?}\n
            - w_r -> {:?}\n
            - w_o -> {:?}\n",
                i,
                qm,
                ql,
                qr,
                qo,
                qc,
                qarith,
                a,
                b,
                c,
            );

            let k = qarith * ((qm * a * b) + (ql * a) + (qr * b) + (qo * c) + pi + qc);

            assert_eq!(k, F::zero(), "Check failed at gate {}", i,);
        }
    }
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
