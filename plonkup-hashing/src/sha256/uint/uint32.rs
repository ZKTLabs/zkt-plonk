use core::marker::PhantomData;
use alloc::vec::Vec;
use ark_ff::Field;
use plonkup_core::constraint_system::{
    Variable, ConstraintSystem, Selectors, LTVariable,
};

use super::{uint8::Uint8Var, Uint1to16Var, Uint8};

///
#[derive(Debug, Clone)]
pub struct Uint8x4<F: Field>(pub Vec<Uint8<F>>);

impl<F: Field> Uint8x4<F> {
    fn constant(value: u32) -> Self {
        let bytes = vec![
            Uint8::Constant(value as u8),
            Uint8::Constant((value >> 8) as u8),
            Uint8::Constant((value >> 16) as u8),
            Uint8::Constant((value >> 24) as u8),
        ];
        
        Self(bytes)
    }

    fn to_uint32(&self, cs: &mut ConstraintSystem<F>) -> Uint32<F> {
        assert_eq!(self.0.len(), 4);

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
        assert_eq!(self.0.len(), 4);
        assert_eq!(other.0.len(), 4);

        let bytes = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(x, y)| x.and(cs, y))
            .collect();
        
        Self(bytes)
    }

    fn xor(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        assert_eq!(self.0.len(), 4);
        assert_eq!(other.0.len(), 4);

        let bytes = self
            .0
            .iter()
            .zip(other.0.iter())
            .map(|(x, y)| x.xor(cs, y))
            .collect();
        
        Self(bytes)
    }

    fn not_and(&self, cs: &mut ConstraintSystem<F>, other: &Self) -> Self {
        assert_eq!(self.0.len(), 4);
        assert_eq!(other.0.len(), 4);

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
pub(crate) struct Uint32Var<F: Field> {
    pub value: u32,
    pub lt_var: LTVariable<F>,
    _p: PhantomData<F>,
}

impl<F: Field> Uint32Var<F> {
    #[cfg(test)]
    pub fn assign_laxly(cs: &mut ConstraintSystem<F>, value: u32) -> Self {
        // Assign uint32 variable without bits constrain
        let var = cs.assign_variable(value.into());
        Self {
            value,
            lt_var: var.into(),
            _p: Default::default(),
        }
    }

    fn shr(&self, cs: &mut ConstraintSystem<F>, n: u32) -> Self {
        assert!(n > 0 && n < 32);

        // self = 2^N * hi + lo
        let hi_value = self.value >> n;
        let lo_value = self.value - (hi_value << n);
        
        let (lo_var, hi_var): (Variable, Variable);
        if n <= 16 {
            // lo is N bits range
            let lo = Uint1to16Var::assign(cs, n, lo_value as u16);
            let hi = cs.assign_variable(hi_value.into());

            lo_var = lo.var;
            hi_var = hi;
        } else {
            // hi is (32-N) bits range
            let lo = cs.assign_variable(lo_value.into());
            let hi = Uint1to16Var::assign(cs, 32 - n, hi_value as u16);

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
            let lo = Uint1to16Var::assign(cs, n, lo_value as u16);
            let hi = cs.assign_variable(hi_value.into());

            lo_var = lo.var;
            hi_var = hi;
        } else {
            // hi is (32-N) bits range
            let lo = cs.assign_variable(lo_value.into());
            let hi = Uint1to16Var::assign(cs, 32 - n, hi_value as u16);

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
            -F::from(1u64 << 32),
            constant.into(),
        );

        // mod_sum = mid * 2^16 + lo
        // lo and mid are 16 bit range.
        let lo_value = sum_value as u16;
        let mid_value = (sum_value >> 16) as u16;

        let lo = Uint1to16Var::assign(cs, 16, lo_value);
        let mid = Uint1to16Var::assign(cs, 16, mid_value);

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
            value: sum_value as u32,
            lt_var: mod_sum.into(),
            _p: Default::default(),
        }
    }
}

///
#[derive(Debug, Clone)]
pub(crate) enum Uint32<F: Field> {
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
                    constant = constant.wrapping_add(v);
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
pub(crate) enum Uint8x4or32<F: Field> {
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
            .collect();

        Self::Uint32(Uint32::mod_add(cs, operands))
    }

    pub fn into_uint8x4(self, cs: &mut ConstraintSystem<F>) -> Uint8x4<F> {
        match self {
            Self::Uint8x4(bytes) => bytes,
            Self::Uint32(var) => var.to_uint8x4(cs),
        }
    }
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use ark_ff::Field;
    use ark_std::{UniformRand, test_rng};
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use plonkup_core::{batch_test_field, constraint_system::test_gate_constraints};

    use super::*;

    fn test_constant_uint8x4_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        let bytes = Uint8x4::constant(value);
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let result = bytes.to_uint32(cs);
                assert_matches!(result, Uint32::Constant(v) => {
                    assert_eq!(v, value);
                });

                vec![]
            },
            &[],
        );
    }

    macro_rules! impl_uint8x4_to_uint32_processor {
        ($value:expr, $(|$cs:ident, $val:ident| $alloc:block),+) => {
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let mut checking = Vec::new();
                $(
                    let allocate = |$cs: &mut ConstraintSystem<F>, $val: u32| $alloc;
                    let bytes = allocate(cs, $value);
                    let result = bytes.to_uint32(cs);
                    assert_matches!(result, Uint32::Variable(u32_var) => {
                        checking.push((u32_var.lt_var, $value.into()));
                    });
                )+

                checking
            }
        };
    }

    fn test_uint8x4_with_1_var_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            impl_uint8x4_to_uint32_processor!(
                value,
                // case 1: [variable, constant, constant, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 2: [constant, variable, constant, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 3: [constant, constant, variable, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 4: [constant, constant, constant, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                }
            ),
            &[],
        )
    }

    fn test_uint8x4_with_2_vars_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            impl_uint8x4_to_uint32_processor!(
                value,
                // case 1: [variable, variable, constant, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 2: [variable, constant, variable, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 3: [variable, constant, constant, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                },
                // case 4: [constant, variable, variable, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 5: [constant, variable, constant, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                },
                // case 6: [constant, constant, variable, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                }
            ),
            &[],
        )
    }

    fn test_uint8x4_with_3_vars_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            impl_uint8x4_to_uint32_processor!(
                value,
                // case 1: [variable, variable, variable, constant]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Constant((val >> 24) as u8),
                    ])
                },
                // case 2: [variable, variable, constant, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Constant((val >> 16) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                },
                // case 3: [variable, constant, variable, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Constant((val >> 8) as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                },
                // case 4: [constant, variable, variable, variable]
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Constant(val as u8),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                }
            ),
            &[],
        )
    }

    fn test_uint8x4_with_4_vars_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            impl_uint8x4_to_uint32_processor!(
                value,
                |cs, val| {
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, val as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 8) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 16) as u8)),
                        Uint8::Variable(Uint8Var::assign(cs, (val >> 24) as u8)),
                    ])
                }
            ),
            &[],
        );
    }

    fn test_uint32_var_shr<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new();

                let var = Uint32Var::assign_laxly(cs, value);
                // case 1
                let result = var.shr(cs, 1);
                checking.push((result.lt_var, (value >> 1).into()));

                // case 2
                let result = var.shr(cs, 16);
                checking.push((result.lt_var, (value >> 16).into()));

                // case 3
                let result = var.shr(cs, 31);
                checking.push((result.lt_var, (value >> 31).into()));

                checking
            },
            &[],
        )
    }

    fn test_uint32_var_rotr<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new();

                let var = Uint32Var::assign_laxly(cs, value);
                // case 1
                let result = var.rotr(cs, 1);
                checking.push((result.lt_var, value.rotate_right(1).into()));

                // case 2
                let result = var.rotr(cs, 16);
                checking.push((result.lt_var, value.rotate_right(16).into()));

                // case 3
                let result = var.rotr(cs, 31);
                checking.push((result.lt_var, value.rotate_right(31).into()));

                checking
            },
            &[],
        )
    }

    fn test_uint32_var_mod_add<F: Field>() {
        let rng = &mut test_rng();
        let constant = u32::rand(rng);
        let operands = [u32::rand(rng), u32::rand(rng), u32::rand(rng)];
        
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new();

                // case 1
                let operand_vars = [
                    Uint32Var::assign_laxly(cs, operands[0].into()),
                ];
                let result = Uint32Var::mod_add(cs, constant, &operand_vars);
                checking.push((result.lt_var, constant.wrapping_add(operands[0]).into()));

                // case 2
                let operand_vars = [
                    Uint32Var::assign_laxly(cs, operands[0].into()),
                    Uint32Var::assign_laxly(cs, operands[1].into()),
                ];
                let result = Uint32Var::mod_add(cs, constant, &operand_vars);
                checking.push((
                    result.lt_var,
                    constant
                        .wrapping_add(operands[0])
                        .wrapping_add(operands[1])
                        .into(),
                ));

                // case 3
                let operand_vars = [
                    Uint32Var::assign_laxly(cs, operands[0].into()),
                    Uint32Var::assign_laxly(cs, operands[1].into()),
                    Uint32Var::assign_laxly(cs, operands[2].into()),
                ];
                let result = Uint32Var::mod_add(cs, constant, &operand_vars);
                checking.push((
                    result.lt_var,
                    constant
                        .wrapping_add(operands[0])
                        .wrapping_add(operands[1])
                        .wrapping_add(operands[2])
                        .into(),
                ));

                checking
            },
            &[],
        )
    }

    fn test_uint32_into_uint8x4<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        // case 1
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let bytes = Uint32::Constant(value).to_uint8x4(cs); 
                for (i, byte) in bytes.0.into_iter().enumerate() {
                    assert_matches!(byte, Uint8::Constant(v) => {
                        assert_eq!(v, (value >> (i * 8)) as u8);
                    });
                }

                vec![]
            },
            &[],
        );

        // case 2
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new(); 

                let var = Uint32Var::assign_laxly(cs, value);
                let bytes = Uint32::Variable(var).to_uint8x4(cs); 
                for (i, byte) in bytes.0.into_iter().enumerate() {
                    assert_matches!(byte, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), ((value >> (i * 8)) as u8).into()));
                    });
                }

                checking
            },
            &[],
        )

    }

    batch_test_field!(
        Bn254,
        [
            test_constant_uint8x4_to_uint32,
            test_uint8x4_with_1_var_to_uint32,
            test_uint8x4_with_2_vars_to_uint32,
            test_uint8x4_with_3_vars_to_uint32,
            test_uint8x4_with_4_vars_to_uint32,
            test_uint32_var_shr,
            test_uint32_var_rotr,
            test_uint32_var_mod_add,
            test_uint32_into_uint8x4
        ],
        []
    );

    batch_test_field!(
        Bls12_381,
        [
            test_constant_uint8x4_to_uint32,
            test_uint8x4_with_1_var_to_uint32,
            test_uint8x4_with_2_vars_to_uint32,
            test_uint8x4_with_3_vars_to_uint32,
            test_uint8x4_with_4_vars_to_uint32,
            test_uint32_var_shr,
            test_uint32_var_rotr,
            test_uint32_var_mod_add,
            test_uint32_into_uint8x4
        ],
        []
    );
}
