
mod uint;

use std::vec::Vec;
use ark_ff::Field;
use plonk_core::constraint_system::ConstraintSystem;
use uint::{Uint8, Uint8x4, Uint32, Uint8x4or32};

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

fn get_sha256_iv<F: Field>() -> Vec<Uint8x4or32<F>> {
    IV.iter().map(|v| Uint8x4or32::Uint32(Uint32::Constant(*v))).collect()
}

fn sha256_compress<F: Field>(
    cs: &mut ConstraintSystem<F>,
    input: &[Uint8<F>],
    cur_hash: &mut [Uint8x4or32<F>],
) {
    assert_eq!(input.len(), 64);
    assert_eq!(cur_hash.len(), 8);

    let mut w = Vec::with_capacity(64);
    for bytes in input.chunks(4) {
        let mut bytes = bytes.to_vec();
        bytes.reverse();
        w.push(Uint8x4or32::Uint8x4(Uint8x4(bytes)));
    }

    for i in 16..64 {
        // s0 = (w[i-15] rotr 7) xor (w[i-15] rotr 18) xor (w[i-15] >> 3)
        let x = w[i - 15].rotr(cs, 7);
        let y = w[i - 15].rotr(cs, 18);
        let z = w[i - 15].shr(cs, 3);
        let s0 = x.xor(cs, &y).xor(cs, &z);

        // s1 = (w[i-2] rotr 17) xor (w[i-2] rotr 19) xor (w[i-2] >> 10)
        let x = w[i - 2].rotr(cs, 17);
        let y = w[i - 2].rotr(cs, 19);
        let z = w[i - 2].shr(cs, 10);
        let s1 = x.xor(cs, &y).xor(cs, &z);

        // w[i] = w[i-16] + s0 + w[i-7] + s1
        let w_i = Uint8x4or32::mod_add(
            cs,
            vec![w[i - 16].clone(), s0, w[i - 7].clone(), s1],
        );
        w.push(w_i);
    }

    assert_eq!(w.len(), 64);

    let mut a = cur_hash[0].clone();
    let mut b = cur_hash[1].clone();
    let mut c = cur_hash[2].clone();
    let mut d = cur_hash[3].clone();
    let mut e = cur_hash[4].clone();
    let mut f = cur_hash[5].clone();
    let mut g = cur_hash[6].clone();
    let mut h = cur_hash[7].clone();

    for i in 0..64 {
        // s1 = (e rotr 6) xor (e rotr 11) xor (e rotr 25)
        let x = e.rotr(cs, 6);
        let y = e.rotr(cs, 11);
        let z = e.rotr(cs, 25);
        let s1 = x.xor(cs, &y).xor(cs, &z);

        // ch = (e and f) xor ((not e) and g)
        let x = e.and(cs, &f);
        let y = e.not_and(cs, &g);
        let ch = x.xor(cs, &y);

        // tmp1 = h + s1 + ch + k[i] + w[i]
        let tmp1 = Uint8x4or32::mod_add(
            cs,
            vec![
                h.clone(),
                s1,
                ch,
                Uint8x4or32::Uint32(Uint32::Constant(ROUND_CONSTANTS[i])),
                w[i].clone(),
            ],
        );

        // s0 = (a rotr 2) xor (a rotr 13) xor (a rotr 22)
        let x = a.rotr(cs, 2);
        let y = a.rotr(cs, 13);
        let z = a.rotr(cs, 22);
        let s0 = x.xor(cs, &y).xor(cs, &z);
        
        // maj = (a and b) xor (a and c) xor (b and c)
        let x = a.and(cs, &b);
        let y = a.and(cs, &c);
        let z = b.and(cs, &c);
        let maj = x.xor(cs, &y).xor(cs, &z);

        let tmp2 = Uint8x4or32::mod_add(cs, vec![s0, maj]);

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
        h = g.clone();
        g = f.clone();
        f = e.clone();
        e = Uint8x4or32::mod_add(cs, vec![d.clone(), tmp1.clone()]);
        d = c.clone();
        c = b.clone();
        b = a.clone();
        a = Uint8x4or32::mod_add(cs, vec![tmp1.clone(), tmp2.clone()]);

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
        cur_hash[0] = Uint8x4or32::mod_add(cs, vec![cur_hash[0].clone(), a.clone()]);
        cur_hash[1] = Uint8x4or32::mod_add(cs, vec![cur_hash[1].clone(), b.clone()]);
        cur_hash[2] = Uint8x4or32::mod_add(cs, vec![cur_hash[2].clone(), c.clone()]);
        cur_hash[3] = Uint8x4or32::mod_add(cs, vec![cur_hash[3].clone(), d.clone()]);
        cur_hash[4] = Uint8x4or32::mod_add(cs, vec![cur_hash[4].clone(), e.clone()]);
        cur_hash[5] = Uint8x4or32::mod_add(cs, vec![cur_hash[5].clone(), f.clone()]);
        cur_hash[6] = Uint8x4or32::mod_add(cs, vec![cur_hash[6].clone(), g.clone()]);
        cur_hash[7] = Uint8x4or32::mod_add(cs, vec![cur_hash[7].clone(), h.clone()]);
    }
}

///
pub fn sha256<F: Field>(
    cs: &mut ConstraintSystem<F>,
    input: &[Uint8<F>],
) -> Vec<Uint8<F>> {
    let mut padded = input.to_vec();
    let len = padded.len() as u64;
    // append 1
    padded.push(Uint8::Constant(1));
    // append 0 util minimum length + 8 is a multiple of 64
    while (padded.len() + 8) % 64 != 0 {
        padded.push(Uint8::Constant(0));
    }
    // append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits
    for i in (0..8).rev() {
        padded.push(Uint8::Constant((len >> (i * 8)) as u8));
    }
    assert!(padded.len() % 64 == 0);

    let mut cur_hash = get_sha256_iv();
    for block in padded.chunks(64) {
        sha256_compress(cs, block, &mut cur_hash);
    }

    cur_hash
        .into_iter()
        .flat_map(|hash| {
            let mut bytes = hash.to_uint8x4(cs);
            bytes.0.reverse();
            bytes.0
        })
        .collect()
}