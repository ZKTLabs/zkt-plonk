// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Simple Arithmetic Gates

use ark_ff::Field;

use super::{Variable, ConstraintSystem, Composer, Selectors, LTVariable};

impl<F: Field> ConstraintSystem<F> {
    /// x + y - z = 0
    pub fn add_gate(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) -> Variable {
        let z: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                z = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one())
                    .with_left_lt(x)
                    .with_right_lt(y);

                composer.gate_constrain(x.var, y.var, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = composer.var_map.value_of_lt_var(y);
                let z_value = x_value + y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x.var, y.var, z, None);
            }
        }

        z
    }

    /// x - y - z = 0
    pub fn sub_gate(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) -> Variable {
        let z: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                z = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_left(F::one())
                    .with_right(-F::one())
                    .with_out(-F::one())
                    .with_left_lt(x)
                    .with_right_lt(y);

                composer.gate_constrain(x.var, y.var, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = composer.var_map.value_of_lt_var(y);
                let z_value = x_value - y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x.var, y.var, z, None);
            }
        }

        z
    }

    /// x * y - z = 0
    pub fn mul_gate(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) -> Variable {
        let z: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                z = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_mul(F::one())
                    .with_out(-F::one())
                    .with_left_lt(x)
                    .with_right_lt(y);

                composer.gate_constrain(x.var, y.var, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = composer.var_map.value_of_lt_var(y);
                let z_value = x_value * y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x.var, y.var, z, None);
            }
        }

        z
    }

    /// y * z - x = 0
    pub fn div_gate(&mut self, x: &LTVariable<F>, y: &LTVariable<F>) -> Variable {
        let z: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                z = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_mul(F::one())
                    .with_out(-F::one())
                    .with_left_lt(y)
                    .with_out_lt(x);

                composer.gate_constrain(y.var, z, x.var, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = composer.var_map.value_of_lt_var(y);
                let z_value = x_value / y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(y.var, z, x.var, None);
            }
        }

        z
    }

    /// x^2 - y = 0
    pub fn square_gate(&mut self, x: &LTVariable<F>) -> Variable {
        let y: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                y = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_mul(F::one())
                    .with_out(-F::one())
                    .with_left_lt(x)
                    .with_right_lt(x);

                composer.gate_constrain(x.var, x.var, y, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = x_value.square();

                y = composer.var_map.assign_variable(y_value);
                
                composer.input_wires(x.var, x.var, y, None);
            }
        }

        y
    }

    /// a * x + b * y + c = z
    pub fn linear_transform_gate(
        &mut self,
        x: &LTVariable<F>,
        y: &LTVariable<F>,
        a: F,
        b: F,
        c: F,
    ) -> Variable {
        let z: Variable;
        match &mut self.composer {
            Composer::Setup(composer) => {
                z = composer.perm.new_variable();

                let sels = Selectors::new_arith()
                    .with_left(a)
                    .with_right(b)
                    .with_out(-F::one())
                    .with_constant(c)
                    .with_left_lt(x)
                    .with_right_lt(y);

                composer.gate_constrain(x.var, y.var, z, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_lt_var(x);
                let y_value = composer.var_map.value_of_lt_var(y);
                let z_value = x_value * a + y_value * b + c;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(x.var, y.var, z, None);
            }
        }

        z
    }
}

#[cfg(test)]
mod test {
    use ark_ff::Field;
    use ark_std::test_rng;
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use ark_bls12_377::Bls12_377;

    use crate::{batch_test_field, constraint_system::test_arith_gate};

    use super::ConstraintSystem;

    fn test_add_gate<F: Field>() {
        test_arith_gate(
            |cs: &mut ConstraintSystem<F>| {
                let rng = &mut test_rng();
                let x_value = F::rand(rng);
                let y_value = F::rand(rng);
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let lt_x = x.linear_transform(F::rand(rng), F::rand(rng));
                let lt_y = y.linear_transform(F::rand(rng), F::rand(rng));

                cs.add_gate(&lt_x, &lt_y);
            },
            &[],
        )
    }

    fn test_sub_gate<F: Field>() {
        test_arith_gate(
            |cs: &mut ConstraintSystem<F>| {
                let rng = &mut test_rng();
                let x_value = F::rand(rng);
                let y_value = F::rand(rng);
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let lt_x = x.linear_transform(F::rand(rng), F::rand(rng));
                let lt_y = y.linear_transform(F::rand(rng), F::rand(rng));

                cs.sub_gate(&lt_x, &lt_y);
            },
            &[],
        )
    }

    fn test_mul_gate<F: Field>() {
        test_arith_gate(
            |cs: &mut ConstraintSystem<F>| {
                let rng = &mut test_rng();
                let x_value = F::rand(rng);
                let y_value = F::rand(rng);
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let lt_x = x.linear_transform(F::rand(rng), F::rand(rng));
                let lt_y = y.linear_transform(F::rand(rng), F::rand(rng));

                cs.mul_gate(&lt_x, &lt_y);
            },
            &[],
        )
    }

    fn test_div_gate<F: Field>() {
        test_arith_gate(
            |cs: &mut ConstraintSystem<F>| {
                let rng = &mut test_rng();
                let x_value = F::rand(rng);
                let y_value = F::rand(rng);
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let lt_x = x.linear_transform(F::rand(rng), F::rand(rng));
                let lt_y = y.linear_transform(F::rand(rng), F::rand(rng));

                cs.div_gate(&lt_x, &lt_y);
            },
            &[],
        )
    }

    batch_test_field!(
        Bn254,
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        []
    );

    batch_test_field!(
        Bls12_381,
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        []
    );

    batch_test_field!(
        Bls12_377,
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        []
    );
}
