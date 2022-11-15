
use plonk_core::constraint_system::{Variable, ConstraintSystem};
use plonk_core::lookup::*;
use ark_ff::Field;

///
pub struct Uint8(pub Variable);

impl Uint8 {
    pub fn assign_variable<F: Field>(cs: &mut ConstraintSystem<F>, value: u8) -> Uint8 {
        assert!(cs.lookup_table.contains_table::<U8RangeTable>());

        let x = cs.assign_variable(value.into());
        cs.lookup_gate_constrain::<U8RangeTable>(x, Variable::Zero, Variable::Zero);

        Self(x)
    }

    
}