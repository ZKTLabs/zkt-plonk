// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-Garage. All rights reserved.

use ark_ff::Field;

use crate::lookup::CustomTable;
use crate::error::Error;

use super::{Composer, Variable, ConstraintSystem};

impl<F: Field> ConstraintSystem<F> {
    /// Adds a plookup gate to the circuit with its corresponding
    /// constraints.
    pub fn lookup_gate<T: CustomTable<F>>(
        &mut self,
        a: Variable,
        b: Variable,
    ) -> Result<Variable, Error> {
        let c: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                // Add selector vectors
                composer.q_m.push(F::zero());
                composer.q_l.push(F::zero());
                composer.q_r.push(F::zero());
                composer.q_o.push(F::zero());
                composer.q_c.push(F::zero());

                composer.q_lookup.push(F::one());

                c = composer.perm.new_variable();

                composer.perm.add_variables_to_map(a, b, c, composer.n);

                composer.n += 1;
            }
            Composer::Proving(composer) => {
                let a_value = composer.var_map.value_of_var(a);
                let b_value = composer.var_map.value_of_var(b);
                let c_value = self.lookup_table.lookup::<T>(&a_value, &b_value)?;

                c = composer.var_map.assign_variable(c_value);
                
                composer.w_l.push(a);
                composer.w_r.push(b);
                composer.w_o.push(c);

                composer.n += 1;
            }
        }

        Ok(c)
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
