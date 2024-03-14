
mod bn254_x3;
mod bn254_x4;
mod bn254_x5;

pub use bn254_x3::*;
pub use bn254_x4::*;
pub use bn254_x5::*;

use ark_ff::PrimeField;
use num_bigint::BigUint;

fn parse_vec<F: PrimeField>(arr: &[&str]) -> Vec<F> {
    arr.iter().map(|x| {
        let data = hex::decode(&x[2..])
            .unwrap_or_else(|e| panic!("unable to decode hex string: {e}"));
        let repr = BigUint::from_bytes_le(&data)
            .try_into()
            .unwrap_or_else(|_| panic!("unable to convert BigUint to PrimeField"));
        F::from_repr(repr).unwrap_or_else(|| panic!("unable to convert BigUint to PrimeField"))
    }).collect()
}

fn parse_matrix<F: PrimeField>(mds_entries: &[&[&str]]) -> Vec<Vec<F>> {
    mds_entries.iter().map(|&row| parse_vec(row)).collect()
}