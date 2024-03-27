use ark_poly::GeneralEvaluationDomain;
use plonk_core::{plonk::ZKTPlonk, commitment::KZG10};
use circuits::WithdrawCircuit;
use gadgets::{merkle_tree, note};
use plonk_core::constraint_system::ConstraintSystem;

#[cfg(feature = "bn254")]
pub(crate) type Fr = ark_bn254::Fr;
#[cfg(feature = "bn254")]
pub(crate) type ParingEngine = ark_bn254::Bn254;

#[cfg(feature = "bls12-381")]
type Fr = ark_bls12_381::Fr;
#[cfg(feature = "bls12-381")]
type Engine = ark_bls12_381::Bls12_381;

#[cfg(feature = "ethereum-transcript")]
pub(crate) type Transcript = gadgets::transcript::EthereumTranscript;
#[cfg(feature = "merlin-transcript")]
type Transcript = plonk_core::transcript::MerlinTranscript;

/// Height of the Merkle tree
#[cfg(feature = "height-48")]
pub(crate) const HEIGHT: usize = 48;
#[cfg(feature = "height-64")]
pub(crate) const HEIGHT: usize = 64;

/// Number of inputs of notes
#[cfg(feature = "notes-1")]
pub(crate) const NOTE_INPUTS: usize = 1;
#[cfg(feature = "notes-2")]
pub(crate) const NOTE_INPUTS: usize = 2;
#[cfg(feature = "notes-3")]
pub(crate) const NOTE_INPUTS: usize = 3;
#[cfg(feature = "notes-4")]
pub(crate) const NOTE_INPUTS: usize = 4;
// #[cfg(feature = "notes-5")]
// pub(crate) const NOTE_INPUTS: usize = 5;

/// Size of the table for membership proof
pub(crate) const TABLE_SIZE: usize = 1024;

pub(crate) type Amount = u64;

#[cfg(feature = "poseidon-bn254-x3")]
pub(crate) type FieldHasherInstance = gadgets::poseidon::Bn254x3<ConstraintSystem<Fr, TABLE_SIZE>>;
#[cfg(feature = "poseidon-bn254-x3")]
pub(crate) type NativeFieldHasherInstance = gadgets::poseidon::Bn254x3Native;
#[cfg(feature = "poseidon-bn254-x3")]
pub(crate) type FieldHasherGeneratorInstance = gadgets::poseidon::Bn254x3Generator;

#[cfg(feature = "poseidon-bn254-x4")]
pub(crate) type FieldHasherInstance = gadgets::poseidon::Bn254x4<ConstraintSystem<Fr, TABLE_SIZE>>;
#[cfg(feature = "poseidon-bn254-x4")]
pub(crate) type NativeFieldHasherInstance = gadgets::poseidon::Bn254x4Native;
#[cfg(feature = "poseidon-bn254-x4")]
pub(crate) type FieldHasherGeneratorInstance = gadgets::poseidon::Bn254x4Generator;


#[cfg(feature = "poseidon-bn254-x5")]
pub(crate) type FieldHasherInstance = gadgets::poseidon::Bn254x5<ConstraintSystem<Fr, TABLE_SIZE>>;
#[cfg(feature = "poseidon-bn254-x5")]
pub(crate) type NativeFieldHasherInstance = gadgets::poseidon::Bn254x5Native;
#[cfg(feature = "poseidon-bn254-x5")]
pub(crate) type FieldHasherGeneratorInstance = gadgets::poseidon::Bn254x5Generator;

#[cfg(feature = "kzg10")]
pub(crate) type CommitmentScheme = KZG10<ParingEngine>;

pub(crate) type ZKTPlonkInstance = ZKTPlonk<
    Fr,
    GeneralEvaluationDomain<Fr>,
    CommitmentScheme,
    Transcript,
    WithdrawCircuit<
        Fr,
        Amount,
        FieldHasherGeneratorInstance,
        FieldHasherInstance,
        NOTE_INPUTS,
        HEIGHT,
    >,
    TABLE_SIZE,
>;

pub(crate) type MerkleTreeStore = merkle_tree::MerkleTreeStore<Fr, HEIGHT>;
// pub(crate) type MerkleTree = merkle_tree::MerkleTree<Fr, NativeFieldHasherInstance, HEIGHT>;

pub(crate) type Note = note::Note<Fr, Amount>;
pub(crate) type Notes = note::Notes<Fr, Amount>;