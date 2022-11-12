// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Simple Arithmetic Gates

use ark_ff::Field;

use super::{
    Variable,
    ConstraintSystem,
    Composer, SetupComposer, ProvingComposer,
};

#[derive(Debug, Clone, Copy)]
///
pub struct ArithSelectors<F: Field> {
    q_m: F,
    q_l: F,
    q_r: F,
    q_o: F,
    q_c: F,
}

impl<F: Field> Default for ArithSelectors<F> {
    fn default() -> Self {
        Self {
            q_m: F::zero(),
            q_l: F::zero(),
            q_r: F::zero(),
            q_o: F::zero(),
            q_c: F::zero(),
        }
    }
}

impl<F: Field> ArithSelectors<F> {
    ///
    pub fn with_mul(mut self, q_m: F) -> Self {
        self.q_m = q_m;
        self
    }

    ///
    pub fn with_left(mut self, q_l: F) -> Self {
        self.q_l = q_l;
        self
    }

    ///
    pub fn with_right(mut self, q_r: F) -> Self {
        self.q_r = q_r;
        self
    }

    ///
    pub fn with_out(mut self, q_o: F) -> Self {
        self.q_o = q_o;
        self
    }

    ///
    pub fn with_constant(mut self, q_c: F) -> Self {
        self.q_c = q_c;
        self
    }
}

impl<F: Field> SetupComposer<F> {
    /// Adds an arithmetic gate.
    /// This gate gives total freedom to the end user to implement the
    /// corresponding circuits in the most optimized way possible because
    /// the user has access to the full set of variables, as well as
    /// selector coefficients that take part in the computation of the gate
    /// equation.
    ///
    /// The final constraint added will force the following:
    /// `(a * b) * q_m + a * q_l + b * q_r + q_c + PI + q_o * c = 0`.
    pub fn arith_constrain(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        sels: ArithSelectors<F>,
        with_pi: bool,
    ) {
        // Add selector vectors
        self.q_l.push(sels.q_l);
        self.q_r.push(sels.q_r);
        self.q_m.push(sels.q_m);
        self.q_o.push(sels.q_o);
        self.q_c.push(sels.q_c);

        self.q_lookup.push(F::zero());

        self.perm.add_variables_to_map(w_l, w_r, w_o, self.n);

        if with_pi {
            self.pp.add_input(self.n);
        }

        self.n += 1;
    }
}

impl<F: Field> ProvingComposer<F> {
    ///
    pub fn input_wires(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        pi: Option<F>,
    ) {
        self.w_l.push(w_l);
        self.w_r.push(w_r);
        self.w_o.push(w_o);

        if let Some(pi) = pi {
            self.pi.add_input(self.n, pi);
        }

        self.n += 1;
    }
}

impl<F: Field> ConstraintSystem<F> {
    /// x + y - z = 0
    pub fn add_gate(&mut self, x: Variable, y: Variable) -> Variable {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = composer.var_map.value_of_var(y);
                let z_value = x_value + y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x, y, z, None);
            }
        }

        z
    }

    /// x - y - z = 0
    pub fn sub_gate(&mut self, x: Variable, y: Variable) -> Variable {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_left(F::one())
                    .with_right(-F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = composer.var_map.value_of_var(y);
                let z_value = x_value - y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x, y, z, None);
            }
        }

        z
    }

    /// x * y - z = 0
    pub fn mul_gate(&mut self, x: Variable, y: Variable) -> Variable {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = composer.var_map.value_of_var(y);
                let z_value = x_value * y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x, y, z, None);
            }
        }

        z
    }

    /// y * z - x = 0
    pub fn div_gate(&mut self, x: Variable, y: Variable) -> Variable {
        let z: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(-F::one());

                z = composer.perm.new_variable();

                composer.arith_constrain(x, y, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = composer.var_map.value_of_var(y);
                let z_value = x_value / y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x, y, z, None);
            }
        }

        z
    }
}

#[cfg(test)]
mod test {
    use crate::constraint_system::helper::test_arith_gates;

    use super::*;
    use ark_ff::UniformRand;
    use ark_bn254::Fr;
    use rand_core::OsRng;

    #[test]
    fn test_add_gate() {
        let rng = &mut OsRng;
        test_arith_gates(|cs: &mut ConstraintSystem<Fr>| {
            let x = cs.assign_variable(Fr::rand(rng));
            let y = cs.assign_variable(Fr::rand(rng));
            cs.add_gate(x, y);
        });
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

//     fn test_public_inputs<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let var_one = composer.add_input(F::one());

//                 let should_be_three = composer.arithmetic_gate(|gate| {
//                     gate.witness(var_one, var_one, None)
//                         .add(F::one(), F::one())
//                         .pi(F::one())
//                 });

//                 composer.constrain_to_constant(
//                     should_be_three,
//                     F::from(3u64),
//                     None,
//                 );

//                 let should_be_four = composer.arithmetic_gate(|gate| {
//                     gate.witness(var_one, var_one, None)
//                         .add(F::one(), F::one())
//                         .pi(F::from(2u64))
//                 });

//                 composer.constrain_to_constant(
//                     should_be_four,
//                     F::from(4u64),
//                     None,
//                 );
//             },
//             200,
//         );
//         assert!(res.is_ok(), "{:?}", res.err().unwrap());
//     }

//     fn test_correct_add_mul_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 // Verify that (4+5+5) * (6+7+7) = 280
//                 let four = composer.add_input(F::from(4u64));
//                 let five = composer.add_input(F::from(5u64));
//                 let six = composer.add_input(F::from(6u64));
//                 let seven = composer.add_input(F::from(7u64));

//                 let fourteen = composer.arithmetic_gate(|gate| {
//                     gate.witness(four, five, None)
//                         .add(F::one(), F::one())
//                         .pi(F::from(5u64))
//                 });

//                 let twenty = composer.arithmetic_gate(|gate| {
//                     gate.witness(six, seven, None)
//                         .add(F::one(), F::one())
//                         .fan_in_3(F::one(), seven)
//                 });

//                 // There are quite a few ways to check the equation is correct,
//                 // depending on your circumstance If we already
//                 // have the output wire, we can constrain the output of the
//                 // mul_gate to be equal to it If we do not, we
//                 // can compute it using an `arithmetic_gate`. If the output
//                 // is public, we can also constrain the output wire of the mul
//                 // gate to it. This is what this test does
//                 let output = composer.arithmetic_gate(|gate| {
//                     gate.witness(fourteen, twenty, None).mul(F::one())
//                 });

//                 composer.constrain_to_constant(output, F::from(280u64), None);
//             },
//             200,
//         );
//         assert!(res.is_ok(), "{:?}", res.err().unwrap());
//     }

//     fn test_correct_add_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 let zero = composer.zero_var();
//                 let one = composer.add_input(F::one());

//                 let c = composer.arithmetic_gate(|gate| {
//                     gate.witness(one, zero, None)
//                         .add(F::one(), F::one())
//                         .constant(F::from(2u64))
//                 });

//                 composer.constrain_to_constant(c, F::from(3u64), None);
//             },
//             32,
//         );
//         assert!(res.is_ok(), "{:?}", res.err().unwrap());
//     }

//     fn test_correct_big_add_mul_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 // Verify that (4+5+5) * (6+7+7) + (8*9) = 352
//                 let four = composer.add_input(F::from(4u64));
//                 let five = composer.add_input(F::from(5u64));
//                 let six = composer.add_input(F::from(6u64));
//                 let seven = composer.add_input(F::from(7u64));
//                 let nine = composer.add_input(F::from(9u64));

//                 let fourteen = composer.arithmetic_gate(|gate| {
//                     gate.witness(four, five, None)
//                         .add(F::one(), F::one())
//                         .fan_in_3(F::one(), five)
//                 });

//                 let twenty = composer.arithmetic_gate(|gate| {
//                     gate.witness(six, seven, None)
//                         .add(F::one(), F::one())
//                         .fan_in_3(F::one(), seven)
//                 });

//                 let output = composer.arithmetic_gate(|gate| {
//                     gate.witness(fourteen, twenty, None)
//                         .mul(F::one())
//                         .fan_in_3(F::from(8u64), nine)
//                 });

//                 composer.constrain_to_constant(output, F::from(352u64), None);
//             },
//             200,
//         );
//         assert!(res.is_ok());
//     }

//     fn test_correct_big_arith_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 // Verify that (4*5)*6 + 4*7 + 5*8 + 9*10 + 11 = 289
//                 let a = composer.add_input(F::from(4u64));
//                 let b = composer.add_input(F::from(5u64));
//                 let q_m = F::from(6u64);
//                 let q_l = F::from(7u64);
//                 let q_r = F::from(8u64);
//                 let d = composer.add_input(F::from(9u64));
//                 let q_4 = F::from(10u64);
//                 let q_c = F::from(11u64);

//                 let output = composer.arithmetic_gate(|gate| {
//                     gate.witness(a, b, None)
//                         .mul(q_m)
//                         .add(q_l, q_r)
//                         .fan_in_3(q_4, d)
//                         .constant(q_c)
//                 });

//                 composer.constrain_to_constant(output, F::from(289u64), None);
//             },
//             200,
//         );
//         assert!(res.is_ok());
//     }

//     fn test_incorrect_big_arith_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 // Verify that (4*5)*6 + 4*7 + 5*8 + 9*12 + 11 != 289
//                 let a = composer.add_input(F::from(4u64));
//                 let b = composer.add_input(F::from(5u64));
//                 let q_m = F::from(6u64);
//                 let q_l = F::from(7u64);
//                 let q_r = F::from(8u64);
//                 let d = composer.add_input(F::from(9u64));
//                 let q_4 = F::from(12u64);
//                 let q_c = F::from(11u64);

//                 let output = composer.arithmetic_gate(|gate| {
//                     gate.witness(a, b, None)
//                         .mul(q_m)
//                         .add(q_l, q_r)
//                         .fan_in_3(q_4, d)
//                         .constant(q_c)
//                 });

//                 composer.constrain_to_constant(output, F::from(289u64), None);
//             },
//             200,
//         );
//         assert!(res.is_err());
//     }

//     fn test_incorrect_add_mul_gate<F, P, PC>()
//     where
//         F: PrimeField,
//         P: TEComposerlParameters<BaseField = F>,
//         PC: HomomorphicCommitment<F>,
//     {
//         let res = gadget_tester::<F, P, PC>(
//             |composer: &mut ConstraintSystem<F, P>| {
//                 // Verify that (5+5) * (6+7) != 117
//                 let five = composer.add_input(F::from(5u64));
//                 let six = composer.add_input(F::from(6u64));
//                 let seven = composer.add_input(F::from(7u64));

//                 let five_plus_five = composer.arithmetic_gate(|gate| {
//                     gate.witness(five, five, None).add(F::one(), F::one())
//                 });

//                 let six_plus_seven = composer.arithmetic_gate(|gate| {
//                     gate.witness(six, seven, None).add(F::one(), F::one())
//                 });

//                 let output = composer.arithmetic_gate(|gate| {
//                     gate.witness(five_plus_five, six_plus_seven, None)
//                         .add(F::one(), F::one())
//                 });

//                 composer.constrain_to_constant(output, F::from(117u64), None);
//             },
//             200,
//         );
//         assert!(res.is_err());
//     }

//     // Bls12-381 tests
//     batch_test!(
//         [
//             test_public_inputs,
//             test_correct_add_mul_gate,
//             test_correct_add_gate,
//             test_correct_big_add_mul_gate,
//             test_correct_big_arith_gate,
//             test_incorrect_add_mul_gate,
//             test_incorrect_big_arith_gate
//         ],
//         [] => (
//             Bls12_381, ark_ed_on_bls12_381::EdwardsParameters
//         )
//     );

//     // Bls12-377 tests
//     batch_test!(
//         [
//             test_public_inputs,
//             test_correct_add_mul_gate,
//             test_correct_add_gate,
//             test_correct_big_add_mul_gate,
//             test_correct_big_arith_gate,
//             test_incorrect_add_mul_gate,
//             test_incorrect_big_arith_gate
//         ],
//         [] => (
//             Bls12_377, ark_ed_on_bls12_377::EdwardsParameters
//         )
//     );
// }
