use std::fs::OpenOptions;
use std::path::PathBuf;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

pub(crate) fn deserialize_from_file<De: CanonicalDeserialize>(path: &PathBuf) -> De {
    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap_or_else(|_| panic!("unable to open file {:?}", path));
    CanonicalDeserialize::deserialize_unchecked(file)
        .unwrap_or_else(|_| panic!("unable to deserialize file {:?}", path))
}

pub(crate) fn serialize_to_file<Se: CanonicalSerialize>(se: &Se, path: &PathBuf) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .open(path)
        .unwrap_or_else(|_| panic!("unable to open file {:?}", path));
    se.serialize_unchecked(&mut file)
        .unwrap_or_else(|_| panic!("unable to serialize file {:?}", path))
}