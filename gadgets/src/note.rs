use ark_ff::Field;
use ark_serialize::{Read, Write, CanonicalSerialize, CanonicalDeserialize, SerializationError};

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Clone)]
pub struct Note<F: Field, A: CanonicalSerialize + CanonicalDeserialize + Clone> {
    pub leaf_index: usize,
    pub identifier: F,
    pub amount: A,
    pub secret: F,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Debug, Default)]
pub struct Notes<F: Field, A: CanonicalSerialize + CanonicalDeserialize + Clone>(
    pub Vec<Note<F, A>>,
);
