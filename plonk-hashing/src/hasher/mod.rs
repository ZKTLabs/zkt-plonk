use core::fmt::Debug;

pub mod poseidon;

pub trait FieldHasher<CS, F: Debug + Clone> {

    fn empty_hash() -> F;

    fn reset(&mut self);

    fn hash(&mut self, cs: &mut CS, input: &[F]) -> F;

    fn hash_two(
        &mut self,
        cs: &mut CS,
        left: &F,
        right: &F,
    ) -> F {
        self.hash(cs, &[left.clone(), right.clone()])
    }
}
