mod poseidon;

pub use poseidon::*;

use core::fmt::Debug;
use plonk_core::error::Error;

pub trait FieldHasher<CS, F: Debug + Clone>: Debug + Default {

    fn empty_hash() -> F;

    fn hash(&mut self, cs: &mut CS, input: &[F]) -> Result<F, Error>;

    fn hash_two(
        &mut self,
        cs: &mut CS,
        left: &F,
        right: &F,
    ) -> Result<F, Error> {
        self.hash(cs, &[left.clone(), right.clone()])
    }
}
