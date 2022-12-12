use alloc::vec::Vec;
use ark_ff::Field;
use bitvec::prelude::*;
use plonkup_core::{
    lookup::*,
    impl_uint_operation_table,
    constraint_system::{ConstraintSystem, LTVariable, Selectors},
};

use super::{Uint8, Uint8Var};

impl_uint_operation_table!(
    U8SpreadToU32Table,
    u8,
    u32,
    |x| { spread_u8_to_u32(x) }
);

fn spread_u8_to_u32(value: u8) -> u32 {
    let mut res = 0u32;
    let res_slice = res.view_bits_mut::<Lsb0>();
    value
        .into_bitarray::<Lsb0>()
        .into_iter()
        .enumerate()
        .for_each(|(i, bit)| {
            *res_slice.get_mut(i * 4).unwrap() = bit;
        });

    res
}

fn split_u32_to_u8_array(value: u32) -> [u8; 4] {
    let (mut x0, mut x1, mut x2, mut x3) = (0u8, 0u8, 0u8, 0u8);
    let x0_slice = x0.view_bits_mut::<Lsb0>();
    let x1_slice = x1.view_bits_mut::<Lsb0>();
    let x2_slice = x2.view_bits_mut::<Lsb0>();
    let x3_slice = x3.view_bits_mut::<Lsb0>();
    
    value
        .into_bitarray::<Lsb0>()
        .into_iter()
        .enumerate()
        .for_each(|(i, bit)| {
            match i % 4 {
                0 => *x0_slice.get_mut(i / 4).unwrap() = bit,
                1 => *x1_slice.get_mut(i / 4).unwrap() = bit,
                2 => *x2_slice.get_mut(i / 4).unwrap() = bit,
                3 => *x3_slice.get_mut(i / 4).unwrap() = bit,
                _ => unreachable!("always less than 4"),
            }
        });

    [x0, x1, x2, x3]
}

impl<F: Field> Uint8Var<F> {
    fn spread_to_u32_var(&self, cs: &mut ConstraintSystem<F>) -> Uint32Var<F> {
        let value = <U8SpreadToU32Table as Custom1DMap<F>>::lookup(self.value);
        let var = cs.assign_variable(value.into());
        cs.lookup_1d_gate::<U8SpreadToU32Table>(self.var, var);

        Uint32Var {
            value,
            lt_var: var.into(),
        }
    }
}

///
#[derive(Debug, Clone)]
pub(crate) struct Uint8x4<F: Field>(pub Vec<Uint8<F>>);

impl<F: Field> Uint8x4<F> {
    pub fn constant(value: u32) -> Self {
        let bytes = split_u32_to_u8_array(value)
            .into_iter()
            .map(|byte| Uint8::Constant(byte))
            .collect();
        
        Self(bytes)
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

    pub fn to_uint32(&self, cs: &mut ConstraintSystem<F>) -> Uint32<F> {
        assert_eq!(self.0.len(), 4);

        let mut pairs: Vec<(u8, _)> = Vec::with_capacity(4);
        let constant: u32;
        match self.0[0] {
            Uint8::Variable(var0) => {
                match self.0[1] {
                    Uint8::Variable(var1) => {
                        match self.0[2] {
                            Uint8::Variable(var2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = 0;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        constant = 8 * spread_u8_to_u32(val3);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = 4 * spread_u8_to_u32(val2);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        constant = 4 * spread_u8_to_u32(val2)
                                            + 8 * spread_u8_to_u32(val3);
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
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = 2 * spread_u8_to_u32(val1);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        constant = 2 * spread_u8_to_u32(val1)
                                        + 8 * spread_u8_to_u32(val3);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = 2 * spread_u8_to_u32(val1)
                                        + 4 * spread_u8_to_u32(val2);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1, var0.spread_to_u32_var(cs)));
                                        constant = 2 * spread_u8_to_u32(val1)
                                            + 4 * spread_u8_to_u32(val2)
                                            + 8 * spread_u8_to_u32(val3);
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
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 8 * spread_u8_to_u32(val3);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 4 * spread_u8_to_u32(val2);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((2, var1.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 4 * spread_u8_to_u32(val2)
                                            + 8 * spread_u8_to_u32(val3);
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
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 2 * spread_u8_to_u32(val1);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((4, var2.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 2 * spread_u8_to_u32(val1)
                                            + 8 * spread_u8_to_u32(val3);
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match self.0[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((8, var3.spread_to_u32_var(cs)));
                                        constant = spread_u8_to_u32(val0)
                                            + 2 * spread_u8_to_u32(val1)
                                            + 4 * spread_u8_to_u32(val2);
                                    }
                                    Uint8::Constant(val3) => {
                                        constant = spread_u8_to_u32(val0)
                                            + 2 * spread_u8_to_u32(val1)
                                            + 4 * spread_u8_to_u32(val2)
                                            + 8 * spread_u8_to_u32(val3);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let value = self
            .0
            .iter()
            .enumerate()
            .map(|(i, byte)| spread_u8_to_u32(byte.value()) << i)
            .sum();

        // 4 vars
        match pairs.len() {
            0 => Uint32::Constant(constant),
            1 => {
                let x = pairs[0].1.lt_var.linear_transform(
                    pairs[0].0.into(),
                    constant.into(),
                );

                Uint32::Variable(Uint32Var { value, lt_var: x })
            }
            2 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.lt_var,
                    &pairs[1].1.lt_var,
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                Uint32::Variable(Uint32Var { value, lt_var: x.into() })
            }
            3 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.lt_var,
                    &pairs[1].1.lt_var,
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                // y = x + x2 * k2
                let y = cs.linear_transform_gate(
                    &x.into(),
                    &pairs[2].1.lt_var,
                    F::one(),
                    pairs[2].0.into(),
                    F::zero(),
                );

                Uint32::Variable(Uint32Var { value, lt_var: y.into() })
            }
            4 => {
                // x = r0 * k0 + r1 * k1 + constant
                let x = cs.linear_transform_gate(
                    &pairs[0].1.lt_var,
                    &pairs[1].1.lt_var,
                    pairs[0].0.into(),
                    pairs[1].0.into(),
                    constant.into(),
                );

                // y = r2 * k2 + r3 * k3
                let y = cs.linear_transform_gate(
                    &pairs[2].1.lt_var,
                    &pairs[3].1.lt_var,
                    pairs[2].0.into(),
                    pairs[3].0.into(),
                    F::zero(),
                );

                // z = x + y
                let z = cs.add_gate(&x.into(), &y.into());

                Uint32::Variable(Uint32Var { value, lt_var: z.into() })
            }
            _ => unreachable!("length of pairs always less than 5")
        }
    }

    /// Sigma function 0 in sha256 block decomposition
    /// (x rotr 7) ^ (x rotr 18) ^ (x >> 3)
    /// =======================================
    /// Part 1: x rotr 7
    /// x0' = x3 rotr 1
    /// x1' = x0 rotr 2
    /// x2' = x1 rotr 2
    /// x3' = x2 rotr 2
    /// ---------------------------------------
    /// Part 2: x rotr 18
    /// x0'' = x2 rotr 4
    /// x1'' = x3 rotr 4
    /// x2'' = x0 rotr 5
    /// x3'' = x1 rotr 5
    /// ---------------------------------------
    /// Part 3: x >> 3
    /// x0''' = x3
    /// x1''' = x0 >> 1
    /// x2''' = x1 >> 1
    /// x3''' = x2 >> 1
    /// ---------------------------------------
    /// Part 4: x' ^ x'' ^ x'''
    /// x0 = (x3 rotr 1) ^ (x2 rotr 4) ^ x3
    /// x1 = (x0 rotr 2) ^ (x3 rotr 4) ^ (x0 >> 1)
    /// x2 = (x1 rotr 2) ^ (x0 rotr 5) ^ (x1 >> 1)
    /// x3 = (x2 rotr 2) ^ (x1 rotr 5) ^ (x2 >> 1)
    pub fn sha256_block_s0(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let x3_rotr_1_xor = self.0[3].rotr_1_xor(cs);
        let x2_rotr_4 = self.0[2].rotr(cs, 4);
        let x0 = x3_rotr_1_xor.xor(cs, &x2_rotr_4);

        let x0_rotr_2_xor_shr_1 = self.0[0].rotr_2_xor_shr_1(cs);
        let x3_rotr_4 = self.0[3].rotr(cs, 4);
        let x1 = x0_rotr_2_xor_shr_1.xor(cs, &x3_rotr_4);

        let x1_rotr_2_xor_shr_1 = self.0[1].rotr_2_xor_shr_1(cs);
        let x0_rotr_5 = self.0[0].rotr(cs, 5);
        let x2 = x1_rotr_2_xor_shr_1.xor(cs, &x0_rotr_5);

        let x2_rotr_2_xor_shr_1 = self.0[2].rotr_2_xor_shr_1(cs);
        let x1_rotr_5 = self.0[1].rotr(cs, 5);
        let x3 = x2_rotr_2_xor_shr_1.xor(cs, &x1_rotr_5);

        Self(vec![x0, x1, x2, x3])
    }

    /// Sigma function 1 in sha256 block decomposition
    /// (x rotr 17) ^ (x rotr 19) ^ (x >> 10)
    /// =======================================
    /// Part 1: x rotr 17
    /// x0' = x1 rotr 4
    /// x1' = x2 rotr 4
    /// x2' = x3 rotr 4
    /// x3' = x0 rotr 5
    /// ---------------------------------------
    /// Part 2: x rotr 19
    /// x0'' = x3 rotr 4
    /// x1'' = x0 rotr 5
    /// x2'' = x1 rotr 5
    /// x3'' = x2 rotr 5
    /// ---------------------------------------
    /// Part 3: x >> 10
    /// x0''' = x2 >> 2
    /// x1''' = x3 >> 2
    /// x2''' = x0 >> 3
    /// x3''' = x1 >> 3
    /// ---------------------------------------
    /// Part 4: x' ^ x'' ^ x'''
    /// x0 = (x1 rotr 4) ^ (x3 rotr 4) ^ (x2 >> 2)
    /// x1 = (x2 rotr 4) ^ (x0 rotr 5) ^ (x3 >> 2)
    /// x2 = (x3 rotr 4) ^ (x1 rotr 5) ^ (x0 >> 3)
    /// x3 = (x0 rotr 5) ^ (x2 rotr 5) ^ (x1 >> 3)
    pub fn sha256_block_s1(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let x1_rotr_4 = self.0[1].rotr(cs, 4);
        let x3_rotr_4 = self.0[3].rotr(cs, 4);
        let x2_shr_2 = self.0[2].shr(cs, 2);
        let x0 = x1_rotr_4.xor(cs, &x3_rotr_4).xor(cs, &x2_shr_2);

        let x2_rotr_4 = self.0[2].rotr(cs, 4);
        let x0_rotr_5 = self.0[0].rotr(cs, 5);
        let x3_shr_2 = self.0[3].shr(cs, 2);
        let x1 = x2_rotr_4.xor(cs, &x0_rotr_5).xor(cs, &x3_shr_2);

        let x1_rotr_5 = self.0[1].rotr(cs, 5);
        let x0_shr_3 = self.0[0].shr(cs, 3);
        let x2 = x3_rotr_4.xor(cs, &x1_rotr_5).xor(cs, &x0_shr_3);

        let x2_rotr_5 = self.0[2].rotr(cs, 5);
        let x1_shr_3 = self.0[1].shr(cs, 3);
        let x3 = x0_rotr_5.xor(cs, &x2_rotr_5).xor(cs, &x1_shr_3);

        Self(vec![x0, x1, x2, x3])
    }

    /// Sigma 0 function in sha256 compression
    /// (x rotr 6) ^ (x rotr 11) ^ (x rotr 25)
    /// =======================================
    /// Part 1: x rotr 6
    /// x0' = x2 rotr 1
    /// x1' = x3 rotr 1
    /// x2' = x0 rotr 2
    /// x3' = x1 rotr 2
    /// ---------------------------------------
    /// Part 2: x rotr 11
    /// x0'' = x3 rotr 2
    /// x1'' = x0 rotr 3
    /// x2'' = x1 rotr 3
    /// x3'' = x2 rotr 3
    /// ---------------------------------------
    /// Part 3: x rotr 25
    /// x0''' = x1 rotr 6
    /// x1''' = x2 rotr 6
    /// x2''' = x3 rotr 6
    /// x3''' = x0 rotr 7
    /// ---------------------------------------
    /// Part 4: x' ^ x'' ^ x'''
    /// x0 = (x2 rotr 1) ^ (x3 rotr 2) ^ (x1 rotr 6)
    /// x1 = (x3 rotr 1) ^ (x0 rotr 3) ^ (x2 rotr 6)
    /// x2 = (x0 rotr 2) ^ (x1 rotr 3) ^ (x3 rotr 6)
    /// x3 = (x1 rotr 2) ^ (x2 rotr 3) ^ (x0 rotr 7)
    pub fn sha256_compress_s0(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let x2_rotr_1 = self.0[2].rotr(cs, 1);
        let x3_rotr_2 = self.0[3].rotr(cs, 2);
        let x1_rotr_6 = self.0[1].rotr(cs, 6);
        let x0 = x2_rotr_1.xor(cs, &x3_rotr_2).xor(cs, &x1_rotr_6);

        let x3_rotr_1 = self.0[3].rotr(cs, 1);
        let x0_rotr_3 = self.0[0].rotr(cs, 3);
        let x2_rotr_6 = self.0[2].rotr(cs, 6);
        let x1 = x3_rotr_1.xor(cs, &x0_rotr_3).xor(cs, &x2_rotr_6);

        let x0_rotr_2 = self.0[0].rotr(cs, 2);
        let x1_rotr_3 = self.0[1].rotr(cs, 3);
        let x3_rotr_6 = self.0[3].rotr(cs, 6);
        let x2 = x0_rotr_2.xor(cs, &x1_rotr_3).xor(cs, &x3_rotr_6);

        let x1_rotr_2 = self.0[1].rotr(cs, 2);
        let x2_rotr_3 = self.0[2].rotr(cs, 3);
        let x0_rotr_7 = self.0[0].rotr(cs, 7);
        let x3 = x1_rotr_2.xor(cs, &x2_rotr_3).xor(cs, &x0_rotr_7);

        Self(vec![x0, x1, x2, x3])
    }

    /// Sigma 1 function in sha256 compression
    /// (x rotr 2) ^ (x rotr 13) ^ (x rotr 22)
    /// =======================================
    /// Part 1: x rotr 2
    /// x0' = x2
    /// x1' = x3
    /// x2' = x0 rotr 1
    /// x3' = x1 rotr 1
    /// ---------------------------------------
    /// Part 2: x rotr 13
    /// x0'' = x1 rotr 3
    /// x1'' = x2 rotr 3
    /// x2'' = x3 rotr 3
    /// x3'' = x0 rotr 4
    /// ---------------------------------------
    /// Part 3: x rotr 22
    /// x0''' = x2 rotr 5
    /// x1''' = x3 rotr 5
    /// x2''' = x0 rotr 6
    /// x3''' = x1 rotr 6
    /// ---------------------------------------
    /// Part 4: x' ^ x'' ^ x'''
    /// x0 = x2 ^ (x1 rotr 3) ^ (x2 rotr 5)
    /// x1 = x3 ^ (x2 rotr 3) ^ (x3 rotr 5)
    /// x2 = (x0 rotr 1) ^ (x3 rotr 3) ^ (x0 rotr 6)
    /// x3 = (x1 rotr 1) ^ (x0 rotr 4) ^ (x1 rotr 6)
    pub fn sha256_compress_s1(&self, cs: &mut ConstraintSystem<F>) -> Self {
        let x2_rotr_5_xor = self.0[2].rotr_5_xor(cs);
        let x1_rotr_3 = self.0[1].rotr(cs, 3);
        let x0 = x2_rotr_5_xor.xor(cs, &x1_rotr_3);

        let x3_rotr_5_xor = self.0[3].rotr_5_xor(cs);
        let x2_rotr_3 = self.0[2].rotr(cs, 3);
        let x1 = x3_rotr_5_xor.xor(cs, &x2_rotr_3);

        let x0_rotr_1_xor_rotr_6 = self.0[0].rotr_1_xor_rotr_6(cs);
        let x3_rotr_3 = self.0[3].rotr(cs, 3);
        let x2 = x0_rotr_1_xor_rotr_6.xor(cs, &x3_rotr_3);

        let x1_rotr_1_xor_rotr_6 = self.0[1].rotr_1_xor_rotr_6(cs);
        let x0_rotr_4 = self.0[0].rotr(cs, 4);
        let x3 = x1_rotr_1_xor_rotr_6.xor(cs, &x0_rotr_4);

        Self(vec![x0, x1, x2, x3])
    }

    /// (x and y) xor ((not x) and z)
    pub fn sha256_compress_ch(cs: &mut ConstraintSystem<F>, x: &Self, y: &Self, z: &Self) -> Self {
        let x_and_y = x.and(cs, &y);
        let x_not_and_z = x.not_and(cs, &z);

        x_and_y.xor(cs, &x_not_and_z)
    }

    ///(x and y) xor (x and z) xor (y and z)
    pub fn sha256_compress_maj(cs: &mut ConstraintSystem<F>, x: &Self, y: &Self, z: &Self) -> Self {
        let x_and_y = x.and(cs, &y);
        let x_and_z = x.and(cs, &z);
        let y_and_z = y.and(cs, &z);

        x_and_y.xor(cs, &x_and_z).xor(cs, &y_and_z)
    }
}

///
#[derive(Debug, Clone)]
pub(crate) struct Uint32Var<F: Field> {
    pub value: u32,
    pub lt_var: LTVariable<F>,
}

impl<F: Field> Uint32Var<F> {
    ///
    #[cfg(test)]
    fn assign(cs: &mut ConstraintSystem<F>, value: u32) -> Self {
        // Assign uint32 variable without bits constrain
        let var = cs.assign_variable(value.into());
        Self {
            value,
            lt_var: var.into(),
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

        let lo = cs.assign_variable(lo_value.into());
        cs.contains_gate::<UintRangeTable<16>>(lo);

        let mid = cs.assign_variable(mid_value.into());
        cs.contains_gate::<UintRangeTable<16>>(mid);

        let sels = Selectors::new_arith()
            .with_left(F::one())
            .with_right(F::from(1u32 << 16))
            .with_out(-F::one());

        cs.arith_constrain(
            lo,
            mid,
            mod_sum,
            sels,
            None,
        );

        Self {
            value: sum_value as u32,
            lt_var: mod_sum.into(),
        }
    }
}

///
#[derive(Debug, Clone)]
pub(crate) enum Uint32<F: Field> {
    Constant(u32),
    Variable(Uint32Var<F>),
}

impl<F: Field> Uint32<F> {
    pub fn to_uint8x4(&self, cs: &mut ConstraintSystem<F>) -> Uint8x4<F> {
        match self {
            Self::Constant(value) => Uint8x4::constant(*value),
            Self::Variable(var) => {
                let bytes = split_u32_to_u8_array(var.value);
                let x0 = Uint8Var::assign(cs, bytes[0]);
                let x1 = Uint8Var::assign(cs, bytes[1]);
                let x2 = Uint8Var::assign(cs, bytes[2]);
                let x3 = Uint8Var::assign(cs, bytes[3]);

                let x0_spread = x0.spread_to_u32_var(cs);
                let x1_spread = x1.spread_to_u32_var(cs);
                let x2_spread = x2.spread_to_u32_var(cs);
                let x3_spread = x3.spread_to_u32_var(cs);

                // y = x0 + 2 * x1
                let y = cs.linear_transform_gate(
                    &x0_spread.lt_var,
                    &x1_spread.lt_var,
                    F::one(),
                    F::from(2u8),
                    F::zero(),
                );

                // z = 4 * x2 + 8 * x3
                let z = cs.linear_transform_gate(
                    &x2_spread.lt_var,
                    &x3_spread.lt_var,
                    F::from(4u8),
                    F::from(8u8),
                    F::zero(),
                );

                // x = y + z
                let sels = Selectors::new_arith()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one())
                    .by_out_lt(&var.lt_var);

                cs.arith_constrain(
                    y,
                    z,
                    var.lt_var.var,
                    sels,
                    None,
                );

                Uint8x4(vec![
                    Uint8::Variable(x0),
                    Uint8::Variable(x1),
                    Uint8::Variable(x2),
                    Uint8::Variable(x3),
                ])
            }
        }
    }

    ///
    pub fn from_bytes_be(cs: &mut ConstraintSystem<F>, bytes: &[Uint8<F>]) -> Self {
        assert_eq!(bytes.len(), 4);

        let mut pairs = Vec::with_capacity(4);
        let constant: u32;
        match bytes[0] {
            Uint8::Variable(var0) => {
                match bytes[1] {
                    Uint8::Variable(var1) => {
                        match bytes[2] {
                            Uint8::Variable(var2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        pairs.push((1u32, var3.var));
                                        constant = 0;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        constant = val3 as u32;
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32, var3.var));
                                        constant = (val2 as u32) << 8;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 16, var1.var));
                                        constant = ((val2 as u32) << 8) + val3 as u32;
                                    }
                                }
                            }
                        }
                    }
                    Uint8::Constant(val1) => {
                        match bytes[2] {
                            Uint8::Variable(var2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        pairs.push((1u32, var3.var));
                                        constant = (val1 as u32) << 16;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        constant = ((val1 as u32) << 16) + val3 as u32;
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        pairs.push((1u32, var3.var));
                                        constant = ((val1 as u32) << 16) + ((val2 as u32) << 8);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 24, var0.var));
                                        constant = ((val1 as u32) << 16) + ((val2 as u32) << 8) + val3 as u32;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Uint8::Constant(val0) => {
                match bytes[1] {
                    Uint8::Variable(var1) => {
                        match bytes[2] {
                            Uint8::Variable(var2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        pairs.push((1u32, var3.var));
                                        constant = (val0 as u32) << 24;
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32 << 8, var2.var));
                                        constant = ((val0 as u32) << 24) + val3 as u32;
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 16, var1.var));
                                        pairs.push((1u32, var3.var));
                                        constant = ((val0 as u32) << 24) + ((val2 as u32) << 8);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 16, var1.var));
                                        constant = ((val0 as u32) << 24) + ((val2 as u32) << 8) + val3 as u32;
                                    }
                                }
                            }
                        }
                    }
                    Uint8::Constant(val1) => {
                        match bytes[2] {
                            Uint8::Variable(var2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32 << 8, var2.var));
                                        pairs.push((1u32, var3.var));
                                        constant = ((val0 as u32) << 24) + ((val1 as u32) << 16);
                                    }
                                    Uint8::Constant(val3) => {
                                        pairs.push((1u32 << 8, var2.var));
                                        constant = ((val0 as u32) << 24) + ((val1 as u32) << 16) + val3 as u32;
                                    }
                                }
                            }
                            Uint8::Constant(val2) => {
                                match bytes[3] {
                                    Uint8::Variable(var3) => {
                                        pairs.push((1u32, var3.var));
                                        constant = ((val0 as u32) << 24) + ((val1 as u32) << 16) + ((val2 as u32) << 8);
                                    }
                                    Uint8::Constant(val3) => {
                                        constant = ((val0 as u32) << 24) + ((val1 as u32) << 16) + ((val2 as u32) << 8) + val3 as u32;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let value = bytes
            .iter()
            .rev()
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

                Self::Variable(Uint32Var {
                    value,
                    lt_var: x,
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

                Self::Variable(Uint32Var {
                    value,
                    lt_var: x.into(),
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

                // y = x + r2 * k2
                let y = cs.linear_transform_gate(
                    &x.into(),
                    &pairs[2].1.into(),
                    F::one(),
                    pairs[2].0.into(),
                    F::zero(),
                );

                Self::Variable(Uint32Var {
                    value,
                    lt_var: y.into(),
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

                Self::Variable(Uint32Var {
                    value,
                    lt_var: z.into(),
                })
            }
            _ => unreachable!("length of pairs always less than 5")
        }
    }

    ///
    pub fn to_bytes_be(&self, cs: &mut ConstraintSystem<F>) -> Vec<Uint8<F>> {
        match self {
            Self::Constant(value) => {
                vec![
                    Uint8::Constant((value >> 24) as u8),
                    Uint8::Constant((value >> 16) as u8),
                    Uint8::Constant((value >> 8) as u8),
                    Uint8::Constant(*value as u8),
                ]
            }
            Self::Variable(var) => {
                let x0 = Uint8Var::assign_strictly(cs, (var.value >> 24) as u8);
                let x1 = Uint8Var::assign_strictly(cs, (var.value >> 16) as u8);
                let x2 = Uint8Var::assign_strictly(cs, (var.value >> 8) as u8);
                let x3 = Uint8Var::assign_strictly(cs, var.value as u8);

                // y = 2^24 * x0 + 2^16 * x1
                let y = cs.linear_transform_gate(
                    &x0.var.into(),
                    &x1.var.into(),
                    F::from(1u32 << 24),
                    F::from(1u32 << 16),
                    F::zero(),
                );

                // z = 2^8 * x2 + x3
                let z = cs.linear_transform_gate(
                    &x2.var.into(),
                    &x3.var.into(),
                    F::from(1u32 <<8),
                    F::from(1u32),
                    F::zero(),
                );

                // x = y + z
                let sels = Selectors::new_arith()
                    .with_left(F::one())
                    .with_right(F::one())
                    .with_out(-F::one())
                    .by_out_lt(&var.lt_var);

                cs.arith_constrain(
                    y,
                    z,
                    var.lt_var.var,
                    sels,
                    None,
                );

                vec![
                    Uint8::Variable(x0),
                    Uint8::Variable(x1),
                    Uint8::Variable(x2),
                    Uint8::Variable(x3),
                ]
            }
        }
    }

    ///
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

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use ark_ff::Field;
    use ark_std::{UniformRand, test_rng};
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use plonkup_core::{batch_test_field, constraint_system::test_gate_constraints};

    use super::*;

    #[test]
    fn test_spread_u8_to_u32() {
        let value = 0b1111_1111u8;
        let spreaded = spread_u8_to_u32(value);
        assert_eq!(spreaded, 0b0001_0001_0001_0001_0001_0001_0001_0001u32);
    }

    #[test]
    fn test_split_u32_to_u8_array() {
        let value = 0b1001_0101_0011_0001_1001_0101_0011_0001u32;
        let array = split_u32_to_u8_array(value);
        assert_eq!(array[0], 0b1111_1111u8);
        assert_eq!(array[1], 0b0010_0010u8);
        assert_eq!(array[2], 0b0100_0100u8);
        assert_eq!(array[3], 0b1000_1000u8);
    }

    fn test_constant_uint8x4_to_uint32<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let bytes = Uint8x4::constant(value);
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
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Constant(bytes[1]),
                        Uint8::Constant(bytes[2]),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 2: [constant, variable, constant, constant]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Constant(bytes[2]),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 3: [constant, constant, variable, constant]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Constant(bytes[1]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 4: [constant, constant, constant, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Constant(bytes[1]),
                        Uint8::Constant(bytes[2]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
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
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Constant(bytes[2]),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 2: [variable, constant, variable, constant]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Constant(bytes[1]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 3: [variable, constant, constant, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Constant(bytes[1]),
                        Uint8::Constant(bytes[2]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                    ])
                },
                // case 4: [constant, variable, variable, constant]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 5: [constant, variable, constant, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Constant(bytes[2]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                    ])
                },
                // case 6: [constant, constant, variable, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Constant(bytes[1]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
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
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Constant(bytes[3]),
                    ])
                },
                // case 2: [variable, variable, constant, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Constant(bytes[2]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                    ])
                },
                // case 3: [variable, constant, variable, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Constant(bytes[1]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                    ])
                },
                // case 4: [constant, variable, variable, variable]
                |cs, val| {
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Constant(bytes[0]),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
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
                    let bytes = split_u32_to_u8_array(val);
                    Uint8x4(vec![
                        Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                        Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                    ])
                }
            ),
            &[],
        );
    }

    fn test_uint8x4_sha256_block_s0<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let mut checking = Vec::new();

                let bytes = split_u32_to_u8_array(value);
                let expect = value.rotate_right(7) ^ value.rotate_right(18) ^ (value >> 3);
                let expect = split_u32_to_u8_array(expect);
                let u8x4 = Uint8x4(vec![
                    Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                ]);
                let result = u8x4.sha256_block_s0(cs);
                for (res, exp) in result.0.into_iter().zip(expect) {
                    assert_matches!(res, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), exp.into()))
                    });
                }

                checking
            },
            &[],
        );
    }

    fn test_uint8x4_sha256_block_s1<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let mut checking = Vec::new();

                let bytes = split_u32_to_u8_array(value);
                let expect = value.rotate_right(17) ^ value.rotate_right(19) ^ (value >> 10);
                let expect = split_u32_to_u8_array(expect);
                let u8x4 = Uint8x4(vec![
                    Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                ]);
                let result = u8x4.sha256_block_s1(cs);
                for (res, exp) in result.0.into_iter().zip(expect) {
                    assert_matches!(res, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), exp.into()))
                    });
                }

                checking
            },
            &[],
        );
    }

    fn test_uint8x4_sha256_compress_s0<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let mut checking = Vec::new();

                let bytes = split_u32_to_u8_array(value);
                let expect = value.rotate_right(6) ^ value.rotate_right(11) ^ value.rotate_right(25);
                let expect = split_u32_to_u8_array(expect);
                let u8x4 = Uint8x4(vec![
                    Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                ]);
                let result = u8x4.sha256_compress_s0(cs);
                for (res, exp) in result.0.into_iter().zip(expect) {
                    assert_matches!(res, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), exp.into()))
                    });
                }

                checking
            },
            &[],
        );
    }

    fn test_uint8x4_sha256_compress_s1<F: Field>() {
        let rng = &mut test_rng();
        let value = u32::rand(rng);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| -> Vec<_> {
                let mut checking = Vec::new();

                let bytes = split_u32_to_u8_array(value);
                let expect = value.rotate_right(2) ^ value.rotate_right(13) ^ value.rotate_right(22);
                let expect = split_u32_to_u8_array(expect);
                let u8x4 = Uint8x4(vec![
                    Uint8::Variable(Uint8Var::assign(cs, bytes[0])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[1])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[2])),
                    Uint8::Variable(Uint8Var::assign(cs, bytes[3])),
                ]);
                let result = u8x4.sha256_compress_s1(cs);
                for (res, exp) in result.0.into_iter().zip(expect) {
                    assert_matches!(res, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), exp.into()))
                    });
                }

                checking
            },
            &[],
        );
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
                    Uint32Var::assign(cs, operands[0].into()),
                ];
                let result = Uint32Var::mod_add(cs, constant, &operand_vars);
                checking.push((result.lt_var, constant.wrapping_add(operands[0]).into()));

                // case 2
                let operand_vars = [
                    Uint32Var::assign(cs, operands[0].into()),
                    Uint32Var::assign(cs, operands[1].into()),
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
                    Uint32Var::assign(cs, operands[0].into()),
                    Uint32Var::assign(cs, operands[1].into()),
                    Uint32Var::assign(cs, operands[2].into()),
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
        let expect = split_u32_to_u8_array(value);

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new(); 

                let u32_var = Uint32Var::assign(cs, value);
                let result = Uint32::Variable(u32_var).to_uint8x4(cs); 
                for (res, exp) in result.0.into_iter().zip(expect) {
                    assert_matches!(res, Uint8::Variable(u8_var) => {
                        checking.push((u8_var.var.into(), exp.into()));
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
            test_uint8x4_sha256_block_s0,
            test_uint8x4_sha256_block_s1,
            test_uint8x4_sha256_compress_s0,
            test_uint8x4_sha256_compress_s1,
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
            test_uint8x4_sha256_block_s0,
            test_uint8x4_sha256_block_s1,
            test_uint8x4_sha256_compress_s0,
            test_uint8x4_sha256_compress_s1,
            test_uint32_var_mod_add,
            test_uint32_into_uint8x4
        ],
        []
    );
}
