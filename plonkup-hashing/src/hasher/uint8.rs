use std::marker::PhantomData;

use plonkup_core::{
    lookup::*,
    constraint_system::{ConstraintSystem, Variable},
};
use ark_ff::Field;

///
#[derive(Debug, Clone, Copy)]
pub struct Uint8Var<F: Field> {
    pub(crate) var: Variable,
    pub(crate) value: u8,
    _p: PhantomData<F>,
}

impl<F: Field> Uint8Var<F> {
    ///
    pub fn new(var: Variable, value: u8) -> Self {
        Self {
            var,
            value,
            _p: Default::default(),
        }
    }

    ///
    pub fn assign(cs: &mut ConstraintSystem<F>, value: u8) -> Self {
        Self {
            var: cs.assign_variable(value.into()),
            value,
            _p: Default::default(),
        }
    }

    ///
    pub fn assign_strictly(cs: &mut ConstraintSystem<F>, value: u8) -> Self {
        let var = cs.assign_variable(value.into());
        cs.contains_gate::<UintRangeTable<8>>(var);

        Self {
            var,
            value,
            _p: Default::default(),
        }
    }

    fn and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let value = <U8AndTable as Custom2DMap<F>>::lookup(self.value, other.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_2d_gate::<U8AndTable>(self.var, other.var, var);

        Self {
            var,
            value,
            _p: Default::default(),
        }
    }

    fn xor(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let value = <U8XorTable as Custom2DMap<F>>::lookup(self.value, other.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_2d_gate::<U8XorTable>(self.var, other.var, var);

        Self {
            var,
            value,
            _p: Default::default(),
        }
    }

    fn not_and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let value = <U8NotAndTable as Custom2DMap<F>>::lookup(self.value, other.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_2d_gate::<U8NotAndTable>(self.var, other.var, var);

        Self {
            var,
            value,
            _p: Default::default(),
        }
    }
}

macro_rules! impl_u8_var_self_operation {
    ($($op:literal),+) => {
        impl<F: Field> Uint8Var<F> {
            fn rotr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
                let (value, var): (u8, Variable);
                match n {
                    $(
                        $op => {
                            value = <U8RotrTable<$op> as Custom1DMap<F>>::lookup(self.value);
                            var = cs.assign_variable(value.into());
                            cs.lookup_1d_gate::<U8RotrTable<$op>>(self.var, var);
                        }
                    )+
                    _ => panic!("invalid bits: {}", n)
                };

                Self {
                    var,
                    value,
                    _p: Default::default(),
                }
            }

            fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
                let (value, var): (u8, Variable);
                match n {
                    $(
                        $op => {
                            value = <U8ShrTable<$op> as Custom1DMap<F>>::lookup(self.value);
                            var = cs.assign_variable(value.into());
                            cs.lookup_1d_gate::<U8ShrTable<$op>>(self.var, var);
                        }
                    )+
                    _ => panic!("invalid bits: {}", n)
                };

                Self {
                    var,
                    value,
                    _p: Default::default(),
                }
            }
        }
    };
}

macro_rules! impl_u8_var_operation_with_const {
    ($($op:literal),+) => {
        impl<F: Field> Uint8Var<F> {
            fn and_with_const(&self, cs: &mut ConstraintSystem<F>, y: u8) -> Self {
                let (value, var): (u8, Variable);
                match y {
                    $(
                        $op => {
                            value = <U8AndWithConstTable<$op> as Custom1DMap<F>>::lookup(self.value);
                            var = cs.assign_variable(value.into());
                            cs.lookup_1d_gate::<U8AndWithConstTable<$op>>(self.var, var);
                        }
                    )+
                };

                Self {
                    var,
                    value,
                    _p: Default::default(),
                }
            }

            fn xor_with_const(&self, cs: &mut ConstraintSystem<F>, y: u8) -> Self {
                let (value, var): (u8, Variable);
                match y {
                    $(
                        $op => {
                            value = <U8XorWithConstTable<$op> as Custom1DMap<F>>::lookup(self.value);
                            var = cs.assign_variable(value.into());
                            cs.lookup_1d_gate::<U8XorWithConstTable<$op>>(self.var, var);
                        }
                    )+
                };

                Self {
                    var,
                    value,
                    _p: Default::default(),
                }
            }

            fn not_and_with_const(&self, cs: &mut ConstraintSystem<F>, y: u8) -> Self {
                let (value, var): (u8, Variable);
                match y {
                    $(
                        $op => {
                            value = <U8NotAndWithConstTable<$op> as Custom1DMap<F>>::lookup(self.value);
                            var = cs.assign_variable(value.into());
                            cs.lookup_1d_gate::<U8NotAndWithConstTable<$op>>(self.var, var);
                        }
                    )+
                };

                Self {
                    var,
                    value,
                    _p: Default::default(),
                }
            }
        }
    };
}

impl_u8_var_self_operation!(1, 2, 3, 4, 5, 6, 7);

impl_u8_var_operation_with_const![
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
    32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
    48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
    64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
    80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95,
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111,
    112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127,
    128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143,
    144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159,
    160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175,
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191,
    192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207,
    208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223,
    224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239,
    240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255
];

///
#[derive(Debug, Clone, Copy)]
pub enum Uint8<F: Field> {
    ///
    Variable(Uint8Var<F>),
    ///
    Constant(u8),
}

impl<F: Field> Uint8<F> {
    pub(crate) fn value(&self) -> u8 {
        match self {
            Self::Variable(var) => var.value,
            Self::Constant(v) => *v,
        }
    }

    pub(crate) fn and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Variable(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(x.and(cs, y)),
                    Self::Constant(y) => Self::Variable(x.and_with_const(cs, *y)),
                }
            }
            Self::Constant(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(y.and_with_const(cs, *x)),
                    Self::Constant(y) => Self::Constant(x & y),
                }
            }
        }
    }

    pub(crate) fn xor(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Variable(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(x.xor(cs, y)),
                    Self::Constant(y) => Self::Variable(x.xor_with_const(cs, *y)),
                }
            }
            Self::Constant(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(y.xor_with_const(cs, *x)),
                    Self::Constant(y) => Self::Constant(x ^ y),
                }
            }
        }
    }

    pub(crate) fn not_and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Variable(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(x.not_and(cs, y)),
                    Self::Constant(y) => Self::Variable(x.not_and_with_const(cs, *y)),
                }
            }
            Self::Constant(x) => {
                match other {
                    Self::Variable(y) => Self::Variable(y.and_with_const(cs, !x)),
                    Self::Constant(y) => Self::Constant((!x) & y),
                }
            }
        }
    }

    pub(crate) fn rotr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Variable(x) => Self::Variable(x.rotr(cs, n)),
            Self::Constant(x) => Self::Constant(x.rotate_right(n)),
        }
    }

    pub(crate) fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Variable(x) => Self::Variable(x.shr(cs, n)),
            Self::Constant(x) => Self::Constant(x >> n),
        }
    }
}
