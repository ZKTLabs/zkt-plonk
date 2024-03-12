
mod bn254_x3;
mod bn254_x4;
mod bn254_x5;

pub use bn254_x3::*;
pub use bn254_x4::*;
pub use bn254_x5::*;

use ark_ff::PrimeField;
use hex::{decode, FromHexError};

fn parse_vec<F: PrimeField>(arr: &[&str]) -> Result<Vec<F>, FromHexError> {
    arr.iter().map(|x| {
        let data = decode(&x[2..])?;
        Ok(F::from_le_bytes_mod_order(&data))
    }).collect()
}

fn parse_matrix<F: PrimeField>(
    mds_entries: &[&[&str]],
) -> Result<Vec<Vec<F>>, FromHexError> {
    mds_entries.iter().map(|&row| parse_vec(row)).collect()
}