
mod uint8;
mod uint32;

pub(crate) use uint8::*;
pub(crate) use uint32::*;

use core::marker::PhantomData;
use ark_ff::Field;
use plonkup_core::{
    lookup::UintRangeTable,
    constraint_system::{Variable, ConstraintSystem},
};

// ///
// #[derive(Debug, Clone, Copy)]
// pub struct Uint1to16Var<F: Field> {
//     var: Variable,
//     _p: PhantomData<F>,
// }

// impl<F: Field> Uint1to16Var<F> {
//     pub fn assign(cs: &mut ConstraintSystem<F>, bits: u32, value: u16) -> Self {
//         let var = cs.assign_variable(value.into());
//         match bits {
//             1 => cs.contains_gate::<UintRangeTable<1>>(var),
//             2 => cs.contains_gate::<UintRangeTable<2>>(var),
//             3 => cs.contains_gate::<UintRangeTable<3>>(var),
//             4 => cs.contains_gate::<UintRangeTable<4>>(var),
//             5 => cs.contains_gate::<UintRangeTable<5>>(var),
//             6 => cs.contains_gate::<UintRangeTable<6>>(var),
//             7 => cs.contains_gate::<UintRangeTable<7>>(var),
//             8 => cs.contains_gate::<UintRangeTable<8>>(var),
//             9 => cs.contains_gate::<UintRangeTable<9>>(var),
//             10 => cs.contains_gate::<UintRangeTable<10>>(var),
//             11 => cs.contains_gate::<UintRangeTable<11>>(var),
//             12 => cs.contains_gate::<UintRangeTable<12>>(var),
//             13 => cs.contains_gate::<UintRangeTable<13>>(var),
//             14 => cs.contains_gate::<UintRangeTable<14>>(var),
//             15 => cs.contains_gate::<UintRangeTable<15>>(var),
//             16 => cs.contains_gate::<UintRangeTable<16>>(var),
//             _ => panic!("invalid bits: {}", bits)
//         }

//         Self {
//             var,
//             _p: Default::default(),
//         }
//     }
// }
