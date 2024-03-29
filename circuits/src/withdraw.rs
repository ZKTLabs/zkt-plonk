// Copyright (c) Lone G. All rights reserved.

use core::{iter::Sum, ops::Sub, fmt::Debug, marker::PhantomData};
use ark_ff::Field;
use bitvec::{prelude::Lsb0, view::BitView};
use derivative::Derivative;
use itertools::{Itertools, izip};
use plonk_core::{constraint_system::*, plonk::Circuit, error::Error};
use plonk_hashing::{hasher::{FieldHasher, FieldHasherGenerator}, merkle::PoECircuit};

#[derive(Derivative)]
#[derivative(Debug(bound = ""), Default(bound = ""))]
pub struct WithdrawCircuit<
    F,
    A,
    G,
    H,
    const INPUTS: usize,
    const HEIGHT: usize,
> where
    F: Field,
    A: BitView + Copy + Debug + Default + PartialOrd + Sum<A> + Sub<Output = A> + Into<F>,
    G: Debug,
    H: Debug + Default,
{
    pub hasher: H,
    #[derivative(Default(value = "[F::default(); INPUTS]"))]
    pub secrets: [F; INPUTS],
    #[derivative(Default(value = "[F::default(); INPUTS]"))]
    pub identifiers: [F; INPUTS],
    #[derivative(Default(value = "[A::default(); INPUTS]"))]
    pub amount_inputs: [A; INPUTS],
    #[derivative(Default(value = "[PoECircuit::<F, HEIGHT>::default(); INPUTS]"))]
    pub poe_circuits: [PoECircuit<F, HEIGHT>; INPUTS],
    pub root: F,
    pub new_secret: F,
    pub new_identifier: F,
    pub withdraw_amount: A,
    pub _p: PhantomData<G>,
}

impl<
    F,
    A,
    G,
    H,
    const TABLE_SIZE: usize,
    const INPUTS: usize,
    const HEIGHT: usize,
> Circuit<F, TABLE_SIZE> for WithdrawCircuit<F, A, G, H, INPUTS, HEIGHT>
where
    F: Field,
    A: Copy + Debug + Default + BitView + PartialOrd + Sum<A> + Sub<Output = A> + Into<F>,
    G: FieldHasherGenerator<H::Params>,
    H: FieldHasher<ConstraintSystem<F, TABLE_SIZE>, LTVariable<F>, G>,
{
    fn synthesize(mut self, cs: &mut ConstraintSystem<F, TABLE_SIZE>) -> Result<(), Error> {
        let amount_in = self.amount_inputs.iter().copied().sum::<A>();
        assert!(amount_in >= self.withdraw_amount, "invalid withdraw amount");
        let amount_out = amount_in - self.withdraw_amount;

        // step 1: Existence proof of inputs

        // assign variables
        let amount_in_vars = self.amount_inputs
            .into_iter()
            .map(|amount| cs.assign_variable(amount.into()))
            .collect_vec();
        let identifier_vars = self.identifiers
            .into_iter()
            .map(|identifier| cs.assign_variable(identifier))
            .collect_vec();
        
        let one_var = LTVariable::constant(F::one());
        let pub_root_var = cs.assign_variable(self.root).into();
        // set root public
        cs.set_variable_public(&pub_root_var);
        for (
            &amount_var,
            identifier_var,
            secret,
            poe_circuit,
        ) in izip!(&amount_in_vars, identifier_vars, self.secrets, self.poe_circuits) {
            let secret_var = cs.assign_variable(secret).into();
            let commitment_var = self.hasher.hash(cs, &[secret_var])?;
            
            let secret_var_inv = cs.div_gate(&one_var, &secret_var);
            let nullifier_var = self.hasher.hash(cs, &[secret_var_inv.into()])?;
            // make nullifier public
            cs.set_variable_public(&nullifier_var);

            let leaf_var = self.hasher.hash(
                cs,
                &[identifier_var.into(), amount_var.into(), commitment_var],
            )?;

            let (root_var, _) = poe_circuit.synthesize(cs, &mut self.hasher, &leaf_var)?;
            cs.equal_constrain(&root_var, &pub_root_var);

            // lookup identifier from subset
            cs.lookup_constrain(&identifier_var.into());
        }

        // step 2: Balance proof

        // bit range constrain for amount out
        let amount_out_bits = amount_out
            .view_bits::<Lsb0>()
            .iter()
            .map(|bit| {
                let var = cs.assign_variable((*bit).into());
                cs.boolean_gate(var)
            })
            .collect_vec();
        let amount_out_var = cs.bits_le_constrain(&amount_out_bits);

        let left_var = amount_in_vars[0];
        let mut right_var = Variable::Zero;
        for &amount_var in &amount_in_vars[1..] {
            right_var = cs.add_gate(&right_var.into(), &amount_var.into());
        }
        let sels = Selectors::new()
            .with_left(-F::one())
            .with_right(-F::one())
            .with_out(F::one());
        // set withdraw amount public
        cs.arith_constrain(
            left_var,
            right_var,
            amount_out_var,
            sels,
            Some(self.withdraw_amount.into()),
        );

        // step 3: hash new secret and commitment

        let new_secret_var = cs.assign_variable(self.new_secret).into();
        let new_identifier_var = cs.assign_variable(self.new_identifier).into();
        let new_commitment_var = self.hasher.hash(cs, &[new_secret_var])?;
        let new_leaf_var = self.hasher.hash(
            cs,
            &[new_identifier_var, amount_out_var.into(), new_commitment_var],
        )?;
        // set new identifier
        cs.set_variable_public(&new_identifier_var);
        // set new leaf public
        cs.set_variable_public(&new_leaf_var);

        Ok(())
    }
}

#[cfg(test)]
mod tests {}