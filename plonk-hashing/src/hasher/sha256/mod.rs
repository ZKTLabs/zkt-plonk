mod utils;
mod uint32;

use std::{vec::Vec, collections::HashMap};
use ark_ff::Field;
use plonk_core::constraint_system::ConstraintSystem;
use uint32::{Uint8x4, Uint32};

use crate::hasher::Uint8;

#[allow(clippy::unreadable_literal)]
const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[allow(clippy::unreadable_literal)]
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

fn get_sha256_iv<F: Field>() -> [Uint32<F>; 8] {
    [
        Uint32::Constant(IV[0]),
        Uint32::Constant(IV[1]),
        Uint32::Constant(IV[2]),
        Uint32::Constant(IV[3]),
        Uint32::Constant(IV[4]),
        Uint32::Constant(IV[5]),
        Uint32::Constant(IV[6]),
        Uint32::Constant(IV[7]),
    ]
}

fn lookup_u8x4<F: Field>(
    cs: &mut ConstraintSystem<F>,
    index: usize,
    w_u8x4: &mut HashMap<usize, Uint8x4<F>>,
    w_u32: &HashMap<usize, Uint32<F>>,
) -> Uint8x4<F> {
    w_u8x4
        .get(&index)
        .map(|v| v.clone())
        .unwrap_or_else(|| {
            let v = w_u32.get(&index).unwrap().to_uint8x4(cs);
            w_u8x4.insert(index, v.clone());
            v
        })
}

fn lookup_u32<F: Field>(
    cs: &mut ConstraintSystem<F>,
    index: usize,
    w_u32: &mut HashMap<usize, Uint32<F>>,
    w_u8x4: &HashMap<usize, Uint8x4<F>>,
) -> Uint32<F> {
    w_u32
        .get(&index)
        .map(|v| v.clone())
        .unwrap_or_else(|| {
            let v = w_u8x4.get(&index).unwrap().to_uint32(cs);
            w_u32.insert(index, v.clone());
            v
        })
}

fn sha256_compress<F: Field>(
    cs: &mut ConstraintSystem<F>,
    block: &[Uint8<F>],
    state: &mut [Uint32<F>],
) {
    assert_eq!(block.len(), 64);
    assert_eq!(state.len(), 8);

    let mut w_u8x4 = HashMap::with_capacity(64);
    let mut w_u32 = HashMap::<usize, Uint32<F>>::with_capacity(64);
    for (i, bytes) in block.chunks(4).enumerate() {
        w_u32.insert(i, Uint32::from_bytes_be(cs, bytes));
    }

    for i in 16..64 {
        let s0 = lookup_u8x4(cs, i - 15, &mut w_u8x4, &w_u32)
            .sha256_block_s0(cs);
        let s1 = lookup_u8x4(cs, i - 2, &mut w_u8x4, &w_u32)
            .sha256_block_s1(cs);

        // w[i] = w[i-16] + s0 + w[i-7] + s1
        let operands = vec![
            lookup_u32(cs, i - 16, &mut w_u32, &w_u8x4),
            s0.to_uint32(cs),
            lookup_u32(cs, i - 7, &mut w_u32, &w_u8x4),
            s1.to_uint32(cs),
        ];
        let w_i = Uint32::mod_add(cs, operands);
        w_u32.insert(i, w_i);
    }

    let mut a = state[0].to_uint8x4(cs);
    let mut b = state[1].to_uint8x4(cs);
    let mut c = state[2].to_uint8x4(cs);
    let mut d = state[3].clone();
    let mut e = state[4].to_uint8x4(cs);
    let mut f = state[5].to_uint8x4(cs);
    let mut g = state[6].to_uint8x4(cs);
    let mut h = state[7].clone();

    for i in 0..64 {
        let s0 = e.sha256_compress_s0(cs);
        let ch = Uint8x4::sha256_compress_ch(cs, &e, &f, &g);

        // tmp1 = h + s0 + ch + k[i] + w[i]
        let operands = vec![
            h.clone(),
            s0.to_uint32(cs),
            ch.to_uint32(cs),
            Uint32::Constant(ROUND_CONSTANTS[i]),
            lookup_u32(cs, i,&mut w_u32, &w_u8x4),
        ];
        let tmp1 = Uint32::mod_add(cs, operands);

        let s1 = a.sha256_compress_s1(cs);
        let maj = Uint8x4::sha256_compress_maj(cs, &a, &b, &c);
        let operands = vec![s1.to_uint32(cs), maj.to_uint32(cs)];
        let tmp2 = Uint32::mod_add(cs, operands);

        /*
            h = g
            g = f
            f = e
            e = d + tmp1
            d = c
            c = b
            b = a
            a = tmp1 + tmp2
        */
        if i < 63 {
            h = g.to_uint32(cs);
            g = f.clone();
            f = e.clone();
            e = Uint32::mod_add(cs, vec![d.clone(), tmp1.clone()]).to_uint8x4(cs);
            d = c.to_uint32(cs);
            c = b.clone();
            b = a.clone();
            a = Uint32::mod_add(cs, vec![tmp1, tmp2]).to_uint8x4(cs);
        } else {
            let h = g.to_uint32(cs);
            let g = f.to_uint32(cs);
            let f = e.to_uint32(cs);
            let e = Uint32::mod_add(cs, vec![d.clone(), tmp1.clone()]);
            let d = c.to_uint32(cs);
            let c = b.to_uint32(cs);
            let b = a.to_uint32(cs);
            let a = Uint32::mod_add(cs, vec![tmp1, tmp2]);

            /*
                Add the compressed chunk to the current hash value:
                h0 = h0 + a
                h1 = h1 + b
                h2 = h2 + c
                h3 = h3 + d
                h4 = h4 + e
                h5 = h5 + f
                h6 = h6 + g
                h7 = h7 + h
            */
            state[0] = Uint32::mod_add(cs, vec![state[0].clone(), a]);
            state[1] = Uint32::mod_add(cs, vec![state[1].clone(), b]);
            state[2] = Uint32::mod_add(cs, vec![state[2].clone(), c]);
            state[3] = Uint32::mod_add(cs, vec![state[3].clone(), d]);
            state[4] = Uint32::mod_add(cs, vec![state[4].clone(), e]);
            state[5] = Uint32::mod_add(cs, vec![state[5].clone(), f]);
            state[6] = Uint32::mod_add(cs, vec![state[6].clone(), g]);
            state[7] = Uint32::mod_add(cs, vec![state[7].clone(), h]);
        }
    }
}

///
pub fn sha256<F: Field>(
    cs: &mut ConstraintSystem<F>,
    input: &[Uint8<F>],
) -> Vec<Uint8<F>> {
    let mut padded = input.to_vec();
    let bit_len = 8 * padded.len() as u64;
    // append byte 0x80
    padded.push(Uint8::Constant(0x80));
    // append 0 util minimum length + 8 is a multiple of 64
    while (padded.len() + 8) % 64 != 0 {
        padded.push(Uint8::Constant(0));
    }
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    for i in (0..8).rev() {
        let byte = (bit_len >> (i * 8)) as u8;
        padded.push(Uint8::Constant(byte));
    }
    assert_eq!(padded.len() % 64, 0);

    let mut state = get_sha256_iv();
    for block in padded.chunks(64) {
        sha256_compress(cs, block, &mut state);
    }

    state
        .into_iter()
        .flat_map(|hash| hash.to_bytes_be(cs))
        .collect()
}

#[cfg(test)]
mod test {
    use ark_ff::Field;
    use ark_std::{test_rng, UniformRand};
    use ark_bn254::Bn254;
    use ark_bls12_381::Bls12_381;
    use assert_matches::assert_matches;
    use sha2::{
        compress256, Sha256,
        digest::{
            generic_array::{GenericArray, sequence::GenericSequence},
            typenum::U64, Digest,
        },
    };
    use itertools::Itertools;
    use plonk_core::{batch_test_field, constraint_system::test_gate_constraints};

    use crate::hasher::uint8::Uint8Var;
    use super::*;

    fn test_blank_hash<F: Field>() {
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut expect_state = IV.clone();
                let mut block = GenericArray::<u8, U64>::generate(|_| 0);
                block[0] = 0x80;
                compress256(&mut expect_state, &[block]);

                let mut state = get_sha256_iv();
                let mut block = vec![Uint8::Constant(0); 64];
                block[0] = Uint8::Constant(0x80);
                sha256_compress(cs, &block, &mut state);
                
                expect_state
                    .into_iter()
                    .zip(state)
                    .for_each(|(expect, res)| {
                        assert_matches!(res, Uint32::Constant(res) => {
                            assert_eq!(res, expect)
                        })
                    });

                vec![]
            },
            &[],
        )
    }

    fn test_full_block<F: Field>() {
        let rng = &mut test_rng();
        
        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new();

                let mut expect_state = IV.clone();
                let block = GenericArray::<u8, U64>::generate(|_| u8::rand(rng));
                compress256(&mut expect_state, &[block]);

                let mut state = get_sha256_iv();
                let block = block
                    .iter()
                    .map(|b| Uint8::Variable(Uint8Var::assign(cs, *b)))
                    .collect_vec();
                sha256_compress(cs, &block, &mut state);

                expect_state
                    .into_iter()
                    .zip(state)
                    .for_each(|(expect, res)| {
                        assert_matches!(res, Uint32::Variable(res) => {
                            checking.push((res.lt_var, expect.into()));
                        })
                    });

                assert_eq!(cs.composer.size(), 11903);
                assert_eq!(cs.lookup_table.size(), 271616);

                checking
            },
            &[],
        )
    }

    fn test_sha256<F: Field>() {
        let rng = &mut test_rng();

        test_gate_constraints(
            |cs: &mut ConstraintSystem<F>| {
                let mut checking = Vec::new();

                let mut input = Vec::with_capacity(55);
                let mut input_vars = Vec::with_capacity(55);
                for _ in 0..55 {
                    let byte = u8::rand(rng);
                    input.push(byte);
                    input_vars.push(Uint8::Variable(Uint8Var::assign(cs, byte)));

                    let hash = Sha256::digest(&input);
                    let hash_vars = sha256(cs, &input_vars);

                    hash
                        .to_vec()
                        .into_iter()
                        .zip(hash_vars)
                        .for_each(|(expect, actual)| {
                            assert_matches!(actual, Uint8::Variable(actual) => {
                                checking.push((actual.var.into(), expect.into()));
                            })
                        })
                }

                checking
            },
            &[],
        )
    }

    batch_test_field!(
        Bn254,
        [test_blank_hash, test_full_block, test_sha256],
        []
    );

    batch_test_field!(
        Bls12_381,
        [test_blank_hash, test_full_block, test_sha256],
        []
    );
}
