use plonk_core::{
    lookup::*,
    impl_uint_operation_table,
    constraint_system::ConstraintSystem,
};
use ark_ff::Field;

use crate::hasher::{Uint8Var, Uint8};

// (x rotr 1) xor x
impl_uint_operation_table!(
    U8Rotr1XorTable,
    u8,
    u8,
    |x| { x.rotate_right(1) ^ x }
);

// (x rotr 2) xor (x >> 1)
impl_uint_operation_table!(
    U8Rotr2XorShr1Table,
    u8,
    u8,
    |x| { x.rotate_right(2) ^ (x >> 1) }
);

// (x rotr 5) xor x
impl_uint_operation_table!(
    U8Rotr5XorTable,
    u8,
    u8,
    |x| { x.rotate_right(5) ^ x }
);

// (x rotr 1) xor (x rotr 6)
impl_uint_operation_table!(
    U8Rotr1XorRotr6Table,
    u8,
    u8,
    |x| { x.rotate_right(1) ^ x.rotate_right(6) }
);

impl<F: Field> Uint8Var<F> {
    fn rotr_1_xor(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let value = <U8Rotr1XorTable as Custom1DMap<F>>::lookup(self.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_1d_gate::<U8Rotr1XorTable>(self.var, var);

        Self::new(var, value)
    }

    fn rotr_2_xor_shr_1(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let value = <U8Rotr2XorShr1Table as Custom1DMap<F>>::lookup(self.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_1d_gate::<U8Rotr2XorShr1Table>(self.var, var);

        Self::new(var, value)
    }

    fn rotr_5_xor(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let value = <U8Rotr5XorTable as Custom1DMap<F>>::lookup(self.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_1d_gate::<U8Rotr5XorTable>(self.var, var);

        Self::new(var, value)
    }

    fn rotr_1_xor_rotr_6(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let value = <U8Rotr1XorRotr6Table as Custom1DMap<F>>::lookup(self.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_1d_gate::<U8Rotr1XorRotr6Table>(self.var, var);

        Self::new(var, value)
    }
}

impl<F: Field> Uint8<F> {
    pub(super) fn rotr_1_xor(&self, cs: &mut ConstraintSystem<F>) -> Self {
        match self {
            Self::Constant(x) => Self::Constant(x.rotate_right(1) ^ x),
            Self::Variable(x) => Self::Variable(x.rotr_1_xor(cs)),
        }
    }

    pub(super) fn rotr_2_xor_shr_1(&self, cs: &mut ConstraintSystem<F>) -> Self {
        match self {
            Self::Constant(x) => Self::Constant(x.rotate_right(2) ^ (x >> 1)),
            Self::Variable(x) => Self::Variable(x.rotr_2_xor_shr_1(cs)),
        }
    }

    pub(super) fn rotr_5_xor(&self, cs: &mut ConstraintSystem<F>) -> Self {
        match self {
            Self::Constant(x) => Self::Constant(x.rotate_right(5) ^ x),
            Self::Variable(x) => Self::Variable(x.rotr_5_xor(cs)),
        }
    }

    pub(super) fn rotr_1_xor_rotr_6(&self, cs: &mut ConstraintSystem<F>) -> Self {
        match self {
            Self::Constant(x) => Self::Constant(x.rotate_right(1) ^ x.rotate_right(6)),
            Self::Variable(x) => Self::Variable(x.rotr_1_xor_rotr_6(cs)),
        }
    }
}
