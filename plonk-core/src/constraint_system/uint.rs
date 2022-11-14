

//! Unsigned integer Gates

use ark_ff::Field;

use super::{ArithSelectors, Composer, Variable, ConstraintSystem};

///
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UInt(pub Variable);

// impl<F: Field> ConstraintSystem<F> {
//     pub fn assign_uint(&mut self, x: F) -> UInt {

//     }
// }