// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Boolean Gates

use ark_ff::Field;

use super::{Selectors, Composer, Variable, ConstraintSystem};

///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Boolean(pub(crate) Variable);

impl<F: Field, const TABLE_SIZE: usize> ConstraintSystem<F, TABLE_SIZE> {
    /// Adds a boolean constraint (also known as binary constraint) where
    /// the gate eq. will enforce that the [`Variable`] received is either `0`
    /// or `1` by adding a constraint in the circuit.
    ///
    /// Note that using this constraint with whatever [`Variable`] that is not
    /// representing a value equalling 0 or 1, will always force the equation to
    /// fail.
    /// x * (x - 1) = 0 => x * x - x = 0
    pub fn boolean_gate(&mut self, x: Variable) -> Boolean {
        let sels = Selectors::new()
            .with_mul(F::one())
            .with_out(-F::one());
        
        self.arith_constrain(x, x, x, sels, None);

        Boolean(x)
    }

    /// Performs an AND operation over the two operands.
    /// x * y - z = 0
    pub fn and_gate(&mut self, x: Boolean, y: Boolean) -> Boolean {
        let z: Variable;
        
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.gate_constrain(x.0, y.0, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x.0);
                let y_value = composer.var_map.value_of_var(y.0);
                let z_value = x_value * y_value;
                
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(x.0, y.0, z, None);
            }
        }
        
        Boolean(z)
    }

    /// Performs an OR operation over the two operands
    /// (1 - x) * (1 - y) - (1 - z) = 0 => xy - x - y + z = 0
    pub fn or_gate(&mut self, x: Boolean, y: Boolean) -> Boolean {
        let z: Variable;
        
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_left(-F::one())
                    .with_right(-F::one())
                    .with_out(F::one());

                z = composer.perm.new_variable();

                composer.gate_constrain(x.0, y.0, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x.0);
                let y_value = composer.var_map.value_of_var(y.0);
                let z_value = (F::one() - x_value) * (F::one() - y_value);
                
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(x.0, y.0, z, None);
            }
        }

        Boolean(z)
    }

    /// Calculates `x XOR y`.
    /// 2xy - x - y + z = 0 
    pub fn xor_gate(&mut self, x: Boolean, y: Boolean) -> Boolean {
        let z: Variable;
        
        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_mul(F::from(2u64))
                    .with_left(-F::one())
                    .with_right(-F::one())
                    .with_out(F::one());

                z = composer.perm.new_variable();

                composer.gate_constrain(x.0, y.0, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x.0);
                let y_value = composer.var_map.value_of_var(y.0);
                let z_value = (x_value + y_value) - F::from(2u64) * x_value * y_value;
                
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(x.0, y.0, z, None);
            }
        }

        Boolean(z)
    }

    /// Calculates `(NOT x) AND y`.
    /// (1 - x) * y - z = 0 => -xy + y - z = 0
    pub fn not_and_gate(&mut self, x: Boolean, y: Boolean) -> Boolean {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_mul(-F::one())
                    .with_right(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.gate_constrain(x.0, y.0, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x.0);
                let y_value = composer.var_map.value_of_var(y.0);
                let z_value = y_value * (F::one() - x_value);
                
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(x.0, y.0, z, None);
            }
        }

        Boolean(z)
    }

    /// Calculates `(NOT a) AND (NOT b)`.
    /// (1 - a) * (1 - b) - c = 0 => ab - a - b + 1 - c = 0
    pub fn nor_gate(&mut self, x: Boolean, y: Boolean) -> Boolean {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = Selectors::new()
                    .with_mul(F::one())
                    .with_left(-F::one())
                    .with_right(-F::one())
                    .with_out(-F::one())
                    .with_constant(F::one());

                z = composer.perm.new_variable();

                composer.gate_constrain(x.0, y.0, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x.0);
                let y_value = composer.var_map.value_of_var(y.0);
                let z_value = (F::one() - x_value) * (F::one() - y_value);
                
                z = composer.var_map.assign_variable(z_value);

                composer.input_wires(x.0, y.0, z, None);
            }
        }

        Boolean(z)
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{
//         batch_test, commitment::HomomorphicCommitment,
//         constraint_system::helper::*,
//     };
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use ark_ff::PrimeField;

//     fn test_correct_bool_gate<F, PC>()
//     where
//         F: PrimeField,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, PC>(
//             |composer: &mut ConstraintSystem<F>| {
//                 let zero = composer.zero_var();
//                 let one = composer.add_input(F::one());
//                 composer.boolean_gate_constrain(zero);
//                 composer.boolean_gate_constrain(one);
//             },
//             32,
//         );
//         assert!(res.is_ok())
//     }

//     fn test_incorrect_bool_gate<F, PC>()
//     where
//         F: PrimeField,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, PC>(
//             |composer: &mut ConstraintSystem<F>| {
//                 let zero = composer.add_input(F::from(5u64));
//                 let one = composer.add_input(F::one());
//                 composer.boolean_gate_constrain(zero);
//                 composer.boolean_gate_constrain(one);
//             },
//             32,
//         );
//         assert!(res.is_err())
//     }

//     // Test for Bls12_381
//     batch_test!(
//         [
//             test_correct_bool_gate,
//             test_incorrect_bool_gate
//         ],
//         [] => (
//             Bls12_381, ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Test for Bls12_377
//     batch_test!(
//         [
//             test_correct_bool_gate,
//             test_incorrect_bool_gate
//         ],
//         [] => (
//             Bls12_377, ark_ed_on_bls12_377::EdwardsParameters        )
//     );
// }
