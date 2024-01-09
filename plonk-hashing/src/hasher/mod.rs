mod uint8;
mod sha256;

pub use uint8::{Uint8, Uint8Var};
pub use sha256::sha256;

use ark_ff::Field;
use plonk_core::constraint_system::ConstraintSystem;

///
pub type BytesDigest<F> = Vec<Uint8<F>>;

///
pub trait BytesHasher<F: Field> {
    ///
    fn empty_hash() -> BytesDigest<F>;

    ///
    fn hash(
        cs: &mut ConstraintSystem<F>,
        input: &[Uint8<F>],
    ) -> BytesDigest<F>;

    ///
    fn hash_two(
        cs: &mut ConstraintSystem<F>,
        left: &BytesDigest<F>,
        right: &BytesDigest<F>,
    ) -> BytesDigest<F> {
        let input = [&left[..], &right[..]].concat();
        Self::hash(cs, &input)
    }
}

///
pub struct Sha256Hasher;

impl<F: Field> BytesHasher<F> for Sha256Hasher {
    fn empty_hash() -> BytesDigest<F> {
        vec![Uint8::Constant(0); 32]
    }

    fn hash(
        cs: &mut ConstraintSystem<F>,
        input: &[Uint8<F>],
    ) -> BytesDigest<F> {
        sha256(cs, input)
    }
}
