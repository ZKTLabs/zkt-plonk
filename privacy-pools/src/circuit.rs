
use core::{iter::Sum, ops::Sub};
use ark_ff::Field;
use bitvec::{prelude::Lsb0, view::BitViewSized};
use itertools::{Itertools, izip};
use plonk_core::constraint_system::*;
use plonk_hashing::{hasher::FieldHasher, merkle::binary::PoECircuit};

pub struct WithdrawCircuit<
    F,
    A,
    const INPUTS: usize,
    const HEIGHT: usize,
    const SIZE: usize,
> where
    F: Field,
    A: Clone + BitViewSized + PartialOrd + Sum<A> + Sub<Output = A> + Into<F>,
{
    secrets: [F; INPUTS],
    identifiers: [F; INPUTS],
    amount_inputs: [A; INPUTS],
    poe_witness: [PoECircuit<F, HEIGHT>; INPUTS],
    new_secret: F,
    new_identifier: F,
    withdraw_amount: A,
}

impl<
    F,
    A,
    const INPUTS: usize,
    const HEIGHT: usize,
    const SIZE: usize,
> WithdrawCircuit<F, A, INPUTS, HEIGHT, SIZE>
where
    F: Field,
    A: Clone + BitViewSized + PartialOrd + Sum<A> + Sub<Output = A> + Into<F>,
{
    pub fn synthesize<H: FieldHasher<ConstraintSystem<F>, LTVariable<F>>>(
        self,
        cs: &mut ConstraintSystem<F>,
        hasher: &mut H,
    ) {
        let amount_in = self.amount_inputs.iter().map(|i| i.clone()).sum::<A>();
        assert!(amount_in >= self.withdraw_amount, "invalid withdraw amount");
        let amount_out = amount_in - self.withdraw_amount;

        // step 1: Existance proof of inputs

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
        for (
            &amount_var,
            identifier_var,
            secret,
            poe_witness,
        ) in izip!(&amount_in_vars, identifier_vars, self.secrets, self.poe_witness) {
            let secret_var = cs.assign_variable(secret).into();
            let commitment_var = hasher.hash(cs, &[secret_var]);
            
            let secret_var_inv = cs.div_gate(&one_var, &secret_var);
            let nullifier_var = hasher.hash(cs, &[secret_var_inv.into()]);
            // make nullifier public
            cs.set_variable_public(&nullifier_var);

            let leaf_var = hasher.hash(
                cs,
                &[identifier_var.into(), amount_var.into(), commitment_var.into()],
            );

            let (root_var, _) = poe_witness.synthesize(cs, hasher, &leaf_var);
            // make root public
            cs.set_variable_public(&root_var);

            // lookup identifier from subset
            cs.lookup_constrain(&commitment_var);
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
        cs.arith_constrain(
            left_var,
            right_var,
            amount_out_var,
            sels,
            Some(amount_out.into()),
        );

        // step 3: hash new secret and commitment

        let new_secret_var = cs.assign_variable(self.new_secret).into();
        let new_identifier_var = cs.assign_variable(self.new_identifier).into();
        let new_commitment_var = hasher.hash(cs, &[new_secret_var]);
        let new_leaf_var = hasher.hash(
            cs,
            &[new_identifier_var, amount_out_var.into(), new_commitment_var],
        );
        // set new leaf public
        cs.set_variable_public(&new_leaf_var);
    }
}


#[cfg(test)]
mod tests {


}