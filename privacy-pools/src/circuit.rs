
use ark_ff::Field;
use plonk_core::constraint_system::{ConstraintSystem, LTVariable};
use plonk_hashing::{hasher::FieldHasher, merkle::binary::PoECircuit};

pub struct ULOCircuit<F: Field, const INPUTS: usize, const HEIGHT: usize> {
    secret: F,
    amount_in: [u64; INPUTS],
    poe_witness: [PoECircuit<F, H, HEIGHT>; INPUTS],
    amount_out: u64,
}

impl<F, H, const INPUTS: usize, const HEIGHT: usize> ULOCircuit<F, H, INPUTS, HEIGHT>
where
    F: Field,
    H: FieldHasher<ConstraintSystem<F>, LTVariable<F>>,
{
    pub fn synthesize(mut self, cs: &mut ConstraintSystem<F>, hasher: &mut H) {
        

        // step 1: Compute leaf node for each input
        for input in self.amount_in {
            
        }

    }
}


