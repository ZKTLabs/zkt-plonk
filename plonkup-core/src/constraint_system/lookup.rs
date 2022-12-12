// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.

use ark_ff::Field;

use crate::lookup::*;

use super::{Composer, Variable, ConstraintSystem, Selectors};

impl<F: Field> ConstraintSystem<F> {
    ///
    pub fn contains_gate<T>(&mut self, x: Variable)
    where
        T: CustomTable<F> + CustomSet<F>,
    {
        self.lookup_table.register_table::<T>();
        
        match &mut self.composer {
            Composer::Setup(composer) => {
                let tag = self.lookup_table.table_tag::<T>();
                let sels = Selectors::new_lookup(tag);
                
                composer.gate_constrain(x, Variable::Zero, Variable::Zero, sels, false);
            }
            Composer::Proving(composer) => {
                #[cfg(feature = "check-lookup")]
                {
                    let x_value = composer.var_map.value_of_var(x);
                    self.lookup_table.contains::<T>(&x_value);
                }

                composer.input_wires(x, Variable::Zero, Variable::Zero, None);
            }
        }
    }
    ///
    pub fn lookup_1d_gate<T>(&mut self, x: Variable, y: Variable)
    where
        T: CustomTable<F> + Custom1DMap<F>,
    {
        self.lookup_table.register_table::<T>();

        match &mut self.composer {
            Composer::Setup(composer) => {
                let tag = self.lookup_table.table_tag::<T>();
                let sels = Selectors::new_lookup(tag);

                composer.gate_constrain(x, y, Variable::Zero, sels, false);
            }
            Composer::Proving(composer) => {
                #[cfg(feature = "check-lookup")]
                {
                    let x_value = composer.var_map.value_of_var(x);
                    let expect_y_value = self.lookup_table.lookup_1d::<T>(&x_value);
                    let actual_y_value = composer.var_map.value_of_var(y);
                    assert_eq!(expect_y_value, actual_y_value);
                }

                composer.input_wires(x, y, Variable::Zero, None);
            }
        }
    }
    /// Adds a plookup gate to the circuit with its corresponding
    /// constraints.
    pub fn lookup_2d_gate<T>(&mut self, x: Variable, y: Variable, z: Variable)
    where
        T: CustomTable<F> + Custom2DMap<F>,
    {
        self.lookup_table.register_table::<T>();

        match &mut self.composer {
            Composer::Setup(composer) => {
                let tag = self.lookup_table.table_tag::<T>();
                let sels = Selectors::new_lookup(tag);

                composer.gate_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                #[cfg(feature = "check-lookup")]
                {
                    let x_value = composer.var_map.value_of_var(x);
                    let y_value = composer.var_map.value_of_var(y);
                    let expect_z_value = self.lookup_table.lookup_2d::<T>(&x_value, &y_value);
                    let actual_z_value = composer.var_map.value_of_var(z);
                    assert_eq!(expect_z_value, actual_z_value);
                }

                composer.input_wires(x, y, z, None);
            }
        }
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::{
//         batch_test, commitment::HomomorphicCommitment,
//         constraint_system::helper::*, lookup::LookupTable,
//     };
//     use ark_bls12_377::Bls12_377;
//     use ark_bls12_381::Bls12_381;
//     use rand_core::{OsRng, RngCore};

//     fn test_plookup_xor<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEModelParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let rng = &mut OsRng;

//                 composer.lookup_table = LookupTable::<F>::xor_table(0, 4);

//                 let negative_one = composer.add_input(-F::one());

//                 let rand1 = rng.next_u32() % 16;
//                 let rand2 = rng.next_u32() % 16;
//                 let rand3 = rng.next_u32() % 16;

//                 let rand1_var = composer.add_input(F::from(rand1));
//                 let rand2_var = composer.add_input(F::from(rand2));
//                 let rand3_var = composer.add_input(F::from(rand3));

//                 let xor12 = rand1 ^ rand2;
//                 let xor13 = rand1 ^ rand3;
//                 let xor23 = rand2 ^ rand3;

//                 let xor12_var = composer.add_input(F::from(xor12));
//                 let xor13_var = composer.add_input(F::from(xor13));
//                 let xor23_var = composer.add_input(F::from(xor23));

//                 composer.lookup_gate(
//                     rand1_var,
//                     rand2_var,
//                     xor12_var,
//                     Some(negative_one),
//                     None,
//                 );

//                 composer.lookup_gate(
//                     rand1_var,
//                     rand3_var,
//                     xor13_var,
//                     Some(negative_one),
//                     None,
//                 );

//                 composer.lookup_gate(
//                     rand2_var,
//                     rand3_var,
//                     xor23_var,
//                     Some(negative_one),
//                     None,
//                 );

//                 composer.arithmetic_gate(|gate| {
//                     gate.add(F::one(), F::one())
//                         .witness(rand1_var, rand2_var, None)
//                 });
//                 composer.arithmetic_gate(|gate| {
//                     gate.mul(F::one()).witness(rand2_var, rand3_var, None)
//                 });
//             },
//             256,
//         );
//         assert!(res.is_ok(), "{:?}", res.err().unwrap());
//     }

//     // Bls12-381 tests
//     batch_test!(
//         [
//             test_plookup_xor
//         ],
//         [] => (
//             Bls12_381, ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Bls12-377 tests
//     batch_test!(
//         [
//             test_plookup_xor
//         ],
//         [] => (
//             Bls12_377, ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
