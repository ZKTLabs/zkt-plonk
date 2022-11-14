// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Simple Arithmetic Gates

use ark_ff::Field;

use super::{
    Variable, ConstraintSystem,
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

                composer.arith_constrain(y, z, x, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = composer.var_map.value_of_var(y);
                let z_value = x_value / y_value;

                z = composer.var_map.assign_variable(z_value);
                
                composer.input_wires(y, z, x, None);
            }
        }

        z
    }

    /// x^2 - y = 0
    pub fn square_gate(&mut self, x: Variable) -> Variable {
        let y: Variable;

        match &mut self.composer {
            Composer::Setup(composer) => {
                let sels = ArithSelectors::default()
                    .with_mul(F::one())
                    .with_out(-F::one());

                y = composer.perm.new_variable();

                composer.arith_constrain(x, x, y, sels, false);
            }
            Composer::Proving(composer) => {
                let x_value = composer.var_map.value_of_var(x);
                let y_value = x_value.square();

                y = composer.var_map.assign_variable(y_value);
                
                composer.input_wires(x, x, y, None);
            }
        }

        y
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
                let z_value = x_value + y_value;
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let assigned_z = cs.assign_variable(z_value);
                let computed_z = cs.add_gate(x, y);
                cs.equal_constrain(assigned_z, computed_z);
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
                let z_value = x_value - y_value;
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let assigned_z = cs.assign_variable(z_value);
                let computed_z = cs.sub_gate(x, y);
                cs.equal_constrain(assigned_z, computed_z);
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
                let z_value = x_value * y_value;
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let assigned_z = cs.assign_variable(z_value);
                let computed_z = cs.mul_gate(x, y);
                cs.equal_constrain(assigned_z, computed_z);
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
                let z_value = x_value / y_value;
                let x = cs.assign_variable(x_value);
                let y = cs.assign_variable(y_value);
                let assigned_z = cs.assign_variable(z_value);
                let computed_z = cs.div_gate(x, y);
                cs.equal_constrain(assigned_z, computed_z);
            },
            &[],
        )
    }

    batch_test_field!(
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        [] => (Bn254)
    );

    batch_test_field!(
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        [] => (Bls12_381)
    );

    batch_test_field!(
        [
            test_add_gate,
            test_sub_gate,
            test_mul_gate,
            test_div_gate
        ],
        [] => (Bls12_377)
    );
}
