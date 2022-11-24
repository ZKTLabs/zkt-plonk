use core::marker::PhantomData;
use alloc::vec::Vec;
use itertools::Itertools;
use plonk_core::constraint_system::{Variable, ConstraintSystem, Selectors, LTVariable};
use ark_ff::Field;

use super::{uint8::Uint8Var, Uint1to16, Uint8};

///
#[derive(Debug, Clone)]
pub struct Uint8x4<F: Field>(pub Vec<Uint8<F>>);

impl<F: Field> Uint8x4<F> {
    fn constant(value: u32) -> Self {
        let bytes = (0..4)
            .into_iter()
            .map(|i| {
                Uint8::Constant((value >> (8 * i)) as u8)
            })
            .collect();
        
        Self(bytes)
    }

    fn to_uint32(&self, cs: &mut ConstraintSystem<F>) -> Uint32<F> {
        let mut pairs = Vec::with_capacity(4);
        let constant: u32;
        match self.0[0] {
            Uint8::Variable(var0) => {
                match self.0[1] {
                    Uint8::Variable(var1) => {
                        match self.0[2] {
                            Uint8::Variable(var2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = 0;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        constant = (val3 as u32) << 24;
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = (val2 as u32) << 16;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 8, var1.var));
                                        constant = ((val2 as u32) << 16) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                        }
                    }
                    Uint8::Constant(val1) => {
                        match self.0[2] {
                            Uint8::Variable(var2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = (val1 as u32) << 8;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        constant = ((val1 as u32) << 8) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32, var0.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = ((val1 as u32) << 8) + ((val2 as u32) << 16);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32, var0.var));
                                        constant = ((val1 as u32) << 8) + ((val2 as u32) << 16) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Uint8::Constant(val0) => {
                match self.0[1] {
                    Uint8::Variable(var1) => {
                        match self.0[2] {
                            Uint8::Variable(var2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = val0 as u32;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 16, var2.var));
                                        constant = val0 as u32 + ((val3 as u32) << 24);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 8, var1.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = val0 as u32 + ((val2 as u32) << 16);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 8, var1.var));
                                        constant = val0 as u32 + ((val2 as u32) << 16) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                        }
                    }
                    Uint8::Constant(val1) => {
                        match self.0[2] {
                            Uint8::Variable(var2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 16, var2.var));
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = val0 as u32 + ((val1 as u32) << 8);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 16, var2.var));
                                        constant = val0 as u32 + ((val1 as u32) << 8) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 24, var3.var));
                                        constant = val0 as u32 + ((val1 as u32) << 8) + ((val2 as u32) << 16);
                                    }
                                    Uint8::Constant(val3) => {
                                        constant = val0 as u32 + ((val1 as u32) << 8) + ((val2 as u32) << 16) + ((val3 as u32) << 24);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let value: u32 = self
            .0
            .iter()
            .enumerate()
            .map(|(i, byte)| (byte.value() as u32) << (i * 8))
            .sum();

        // 4 vars
        match pairs.len() {
            0 => Uint32::Constant(constant),
            1 => {
                let x = pairs[0].1.linear_transform(
                    pairs[0].0.into(),
                    constant.into(),
                );

                Uint32::Variable(Uint32Var {
                    value,
                    lt_var: x,
                    _p: PhantomData,
                })
            }
            2 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.into(),
                    &pairs[1].1.into(),
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                Uint32::Variable(Uint32Var {
                    value,
                    lt_var: x.into(),
                    _p: PhantomData,
                })
            }
            3 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.into(),
                    &pairs[1].1.into(),
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                // y = x + x2 * k2
                let y = cs.linear_transform_gate(
                    &x.into(),
                    &pairs[2].1.into(),
                    F::one(),
                    pairs[2].0.into(),
                    F::zero(),
                );

                Uint32::Variable(Uint32Var {
                    value,
                    lt_var: y.into(),
                    _p: Default::default(),
                })
            }
            4 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.into(),
                    &pairs[1].1.into(),
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                // y = r2 * k2 + r3 * k3
                let y = cs.linear_transform_gate(
                    &pairs[2].1.into(),
                    &pairs[3].1.into(),
                    pairs[2].0.into(),
                    pairs[3].0.into(),
                    F::zero(),
                );

                // z = x + y
                let z = cs.add_gate(&x.into(), &y.into());

                Uint32::Variable(Uint32Var {
                    value,
                    lt_var: z.into(),
                    _p: Default::default(),
                })
            }
            _ => unreachable!("length of pairs always less than 5")
        }
    }

    fn and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let bytes = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(x, y)| x.and(cs, y))
            .collect();
        
        Self(bytes)
    }

    fn xor(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let bytes = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(x, y)| x.xor(cs, y))
            .collect();
        
        Self(bytes)
    }

    fn not_and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        let bytes = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(x, y)| x.not_and(cs, y))
            .collect();
        
        Self(bytes)
    }
}

///
#[derive(Debug, Clone)]
pub struct Uint32Var<F: Field> {
    value: u32,
    lt_var: LTVariable<F>,
    _p: PhantomData<F>,
}

impl<F: Field> Uint32Var<F> {
    fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        assert!(n > 0 && n < 32);

        // self = 2^N * hi + lo
        let hi_value = self.value >> n;
        let lo_value = self.value - (hi_value << n);
        
        let (lo_var, hi_var): (Variable, Variable);
        if n <= 16 {
            // lo is N bits range
            let lo = Uint1to16::assign(cs, n, lo_value as u16);
            let hi = cs.assign_variable(hi_value.into());

            lo_var = lo.var;
            hi_var = hi;
        } else {
            // hi is (32-N) bits range
            let lo = cs.assign_variable(lo_value.into());
            let hi = Uint1to16::assign(cs, 32 - n, hi_value as u16);

            lo_var = lo;
            hi_var = hi.var;
        }

        let sels = Selectors::new_arith()
            .with_left(F::one())
            .with_right(F::from(1u32 << n))
            .with_out(-F::one())
            .with_out_lt(&self.lt_var);

        cs.arith_constrain(
            lo_var,
            hi_var,
            self.lt_var.var,
            sels,
            None,
        );

        Self {
            value: hi_value,
            lt_var: hi_var.into(),
            _p: Default::default(),
        }
    }

    fn rotr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        assert!(n > 0 && n < 32);

        // self = 2^N * hi + lo
        let hi_value = self.value >> n;
        let lo_value = self.value - (hi_value << n);

        let (lo_var, hi_var): (Variable, Variable);
        if n <= 16 {
            // lo is in N bits range
            let lo = Uint1to16::assign(cs, n, lo_value as u16);
            let hi = cs.assign_variable(hi_value.into());

            lo_var = lo.var;
            hi_var = hi;
        } else {
            // hi is (32-N) bits range
            let lo = cs.assign_variable(lo_value.into());
            let hi = Uint1to16::assign(cs, 32 - n, hi_value as u16);

            lo_var = lo;
            hi_var = hi.var;
        }

        let sels = Selectors::new_arith()
            .with_left(F::one())
            .with_right(F::from(1u32 << n))
            .with_out(-F::one())
            .with_out_lt(&self.lt_var);

        cs.arith_constrain(
            lo_var,
            hi_var,
            self.lt_var.var,
            sels,
            None,
        );

        // res = 2^(32-N) * lo + hi
        let res = cs.linear_transform_gate(
            &lo_var.into(),
            &hi_var.into(),
            F::from(1u32 << (32 - n)),
            F::one(),
            F::zero(),
        );

        Self {
            value: self.value.rotate_right(n),
            lt_var: res.into(),
            _p: Default::default(),
        }
    }

    ///
    fn mod_add(cs: &mut ConstraintSystem<F>, constant: u32, operands: &[Self]) -> Self {
        assert!(!operands.is_empty());

        // op_sum = op_1 + op_2 + ...
        let op_sum = if operands.len() > 1 {
            let first = cs.add_gate(&operands[0].lt_var, &operands[1].lt_var);
            operands[2..]
                .iter()
                .fold(first, |s, op| {
                    cs.add_gate(&s.into(), &op.lt_var)
                })
                .into()
        } else {
            operands[0].lt_var.clone()
        };

        // op_sum + constant = hi * 2^32 + mod_sum
        let sum_value = constant as u64 + operands.iter().map(|op| op.value as u64).sum::<u64>();
        let hi_value = sum_value >> 32;
        
        let hi = cs.assign_variable(hi_value.into());
        
        let mod_sum = cs.linear_transform_gate(
            &op_sum,
            &hi.into(),
            F::one(),
            F::from(1u64 << 32),
            constant.into(),
        );

        // mod_sum = mid * 2^16 + lo
        // lo and mid are 16 bit range.
        let mod_sum_value = sum_value as u32;
        let lo_value = mod_sum_value as u16;
        let mid_value = (mod_sum_value >> 16) as u16;

        let lo = Uint1to16::assign(cs, 16, lo_value);
        let mid = Uint1to16::assign(cs, 16, mid_value);

        let sels = Selectors::new_arith()
            .with_left(F::one())
            .with_right(F::from(1u32 << 16))
            .with_out(-F::one());

        cs.arith_constrain(
            lo.var,
            mid.var,
            mod_sum,
            sels,
            None,
        );

        Self {
            value: mod_sum_value,
            lt_var: mod_sum.into(),
            _p: Default::default(),
        }
    }
}

///
#[derive(Debug, Clone)]
pub enum Uint32<F: Field> {
    Variable(Uint32Var<F>),
    Constant(u32),
}

impl<F: Field> Uint32<F> {
    pub fn to_uint8x4(&self, cs: &mut ConstraintSystem<F>) -> Uint8x4<F> {
        match self {
            Uint32::Constant(value) => Uint8x4::constant(*value),
            Uint32::Variable(var) => {
                let r0 = Uint8Var::assign(cs, var.value as u8);
                let r1 = Uint8Var::assign(cs, (var.value >> 8) as u8);
                let r2 = Uint8Var::assign(cs, (var.value >> 16) as u8);
                let r3 = Uint8Var::assign(cs, (var.value >> 24) as u8);

                // x = r0 + r1 * 2^8
                let x = cs.linear_transform_gate(
                    &r0.var.into(),
                    &r1.var.into(),
                    F::one(),
                    F::from(1u32 << 8),
                    F::zero(),
                );

                // y = r2 * 2^16 + r3 * 2^24
                let y = cs.linear_transform_gate(
                    &r2.var.into(),
                    &r3.var.into(),
                    F::from(1u32 << 16),
                    F::from(1u32 << 24),
                    F::zero(),
                );
                    
                // var = x + y
                let sels = Selectors::new_arith()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one())
                    .with_out_lt(&var.lt_var);

                cs.arith_constrain(x, y, var.lt_var.var, sels, None);

                Uint8x4(vec![
                    Uint8::Variable(r0),
                    Uint8::Variable(r1),
                    Uint8::Variable(r2),
                    Uint8::Variable(r3),
                ])
            }
        }
    }

    pub fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Variable(var) => Self::Variable(var.shr(cs, n)),
            Self::Constant(v) => Self::Constant(v >> n),
        }
    }

    pub fn rotr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Variable(var) => Self::Variable(var.rotr(cs, n)),
            Self::Constant(v) => Self::Constant(v.rotate_right(n))
        }
    }

    pub fn mod_add(cs: &mut ConstraintSystem<F>, operands: Vec<Self>) -> Self {
        let mut constant = 0u32;
        let mut ops = Vec::with_capacity(operands.len());

        for op in operands {
            match op {
                Self::Variable(var) => ops.push(var),
                Self::Constant(v) => {
                    constant = constant.saturating_add(v);
                }
            }
        }

        if ops.is_empty() {
            Self::Constant(constant)
        } else {
            let var = Uint32Var::mod_add(cs, constant, &ops);
            Self::Variable(var)
        }
    }
}

///
#[derive(Debug, Clone)]
pub enum Uint8x4or32<F: Field> {
    Uint8x4(Uint8x4<F>),
    Uint32(Uint32<F>),
}

impl<F: Field> Uint8x4or32<F> {
    pub fn and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Uint8x4(x) => {
                let z = match other {
                    Self::Uint8x4(y) => x.and(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.and(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
            Self::Uint32(x) => {
                let x = x.to_uint8x4(cs);
                let z = match other {
                    Self::Uint8x4(y) => x.and(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.and(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
        }
    }

    pub fn xor(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Uint8x4(x) => {
                let z = match other {
                    Self::Uint8x4(y) => x.xor(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.xor(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
            Self::Uint32(x) => {
                let x = x.to_uint8x4(cs);
                let z = match other {
                    Self::Uint8x4(y) => x.xor(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.xor(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
        }
    }

    pub fn not_and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        match self {
            Self::Uint8x4(x) => {
                let z = match other {
                    Self::Uint8x4(y) => x.not_and(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.not_and(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
            Self::Uint32(x) => {
                let x = x.to_uint8x4(cs);
                let z = match other {
                    Self::Uint8x4(y) => x.not_and(cs, y),
                    Self::Uint32(y) => {
                        let y = y.to_uint8x4(cs);
                        x.not_and(cs, &y)
                    }
                };
                Self::Uint8x4(z)
            }
        }
    }

    pub fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Uint8x4(bytes) => {
                let var = bytes.to_uint32(cs);
                Self::Uint32(var.shr(cs, n))
            }
            Self::Uint32(var) => Self::Uint32(var.shr(cs, n)),
        }
    }

    pub fn rotr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        match self {
            Self::Uint8x4(bytes) => {
                let var = bytes.to_uint32(cs);
                Self::Uint32(var.rotr(cs, n))
            }
            Self::Uint32(var) => Self::Uint32(var.rotr(cs, n)),
        }
    }

    pub fn mod_add(cs: &mut ConstraintSystem<F>, operands: Vec<Self>) -> Self {
        let operands = operands
            .into_iter()
            .map(|op| {
                match op {
                    Self::Uint8x4(bytes) => bytes.to_uint32(cs),
                    Self::Uint32(var) => var,
                }
            })
            .collect_vec();

        Self::Uint32(Uint32::mod_add(cs, operands))
    }

    pub fn to_uint8x4(self, cs: &mut ConstraintSystem<F>) -> Uint8x4<F> {
        match self {
            Self::Uint8x4(bytes) => bytes,
            Self::Uint32(var) => var.to_uint8x4(cs),
        }
    }
}
