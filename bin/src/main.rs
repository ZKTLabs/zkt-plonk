mod instance;
mod parser;

use std::{path::PathBuf, str::FromStr, rc::Rc, ops::Sub, marker::PhantomData};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_poly_commit::PolynomialCommitment;
use array_init::{array_init, map_array_init};
use clap::Parser;
use ethereum_types::Address;
use num_bigint::BigUint;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use circuits::WithdrawCircuit;
use plonk_core::proof_system::{ExtendedProverKey, ProverKey, VerifierKey};
use plonk_hashing::{
    hasher::{FieldHasher, FieldHasherGenerator},
    merkle::PoECircuit,
};

use crate::{parser::*, instance::*};

#[derive(Debug, Parser)]
#[command(name = "ZKT tools", version = "0.1.0", about = "Helpful tools of ZKT protocol")]
enum Args {
    Compile {
        #[arg(long = "max-degree", short = 'd', default_value = "1048576")]
        max_degree: usize,
        #[arg(long = "ck", default_value = "../../data/ck")]
        ck_path: PathBuf,
        #[arg(long = "cvk", default_value = "../../data/cvk")]
        cvk_path: PathBuf,
        #[arg(long = "pk", default_value = "../../data/pk")]
        pk_path: PathBuf,
        #[arg(long = "epk")]
        epk_path: Option<PathBuf>,
        #[arg(long = "vk", default_value = "../../data/vk")]
        vk_path: PathBuf,
    },
    SetupPoseidon {},
    InitStore {
        #[arg(long = "merkle-tree", short = 't', default_value = "../../data/merkle-tree")]
        tree_path: PathBuf,
        #[arg(long = "notes", short = 'n', default_value = "../../data/notes")]
        notes_path: PathBuf,
    },
    Deposit {
        #[arg(long = "merkle-tree", short = 't', default_value = "../../data/merkle-tree")]
        tree_path: PathBuf,
        #[arg(long = "notes", short = 'n', default_value = "../../data/notes")]
        notes_path: PathBuf,
        #[arg(long, short = 'i')]
        identifier: String,
        #[arg(long, short = 'a', default_value = "1000")]
        amount: String,
    },
    ListNotes {
        #[arg(long = "notes", short = 'n', default_value = "../../data/notes")]
        notes_path: PathBuf,
    },
    ProveWithdraw {
        #[arg(long = "ck", default_value = "../../data/ck")]
        ck_path: PathBuf,
        #[arg(long = "cvk", default_value = "../../data/cvk")]
        cvk_path: PathBuf,
        #[arg(long = "pk", default_value = "../../data/pk")]
        pk_path: PathBuf,
        #[arg(long = "epk")]
        epk_path: Option<PathBuf>,
        #[arg(long = "vk", default_value = "../../data/vk")]
        vk_path: PathBuf,
        #[arg(long = "merkle-tree", short = 't', default_value = "../../data/merkle-tree")]
        tree_path: PathBuf,
        #[arg(long = "notes", short = 'n', default_value = "../../data/notes")]
        notes_path: PathBuf,
        #[arg(long, short = 'x')]
        note_indexes: Vec<usize>,
        #[arg(long = "identifiers-set", short = 's')]
        identifiers_set: Vec<String>,
        #[arg(long, short = 'i')]
        identifier: String,
        #[arg(long, short = 'a')]
        amount: String,
    },
}


fn main() {
    let args = Args::parse();
    match args {
        Args::Compile {
            max_degree,
            ck_path,
            cvk_path,
            pk_path,
            epk_path,
            vk_path,
        } => {
            let rng = &mut StdRng::from_entropy();
            let pp = CommitmentScheme::setup(max_degree, None, rng)
                .unwrap_or_else(|e| panic!("setup KZG10 failed: {e}"));
            let (ck, cvk, pk, epk, vk) =
                ZKTPlonkInstance::compile(epk_path.is_some(), &pp)
                    .unwrap_or_else(|e| panic!("compile ZKTPlonkInstance failed: {e}"));

            serialize_to_file(&ck, &ck_path);
            serialize_to_file(&cvk, &cvk_path);
            serialize_to_file(&pk, &pk_path);
            if let Some(epk_path) = epk_path {
                serialize_to_file(&epk.unwrap(), &epk_path);
            }
            serialize_to_file(&vk, &vk_path);
        }
        Args::SetupPoseidon {} => {
            let constants = FieldHasherGeneratorInstance::generate();
            println!("full rounds = {}", constants.full_rounds);
            println!("partial rounds = {}", constants.partial_rounds);

            println!("round constants = &[");
            for constant in constants.round_constants.iter() {
                println!(" \"{:#}\",", constant.into_repr().to_string());
            }
            println!("];");

            let matrix = &constants.mds_matrices.m;
            println!("mds matrix = &[");
            for row in matrix.iter_rows() {
                println!(" &[");
                for cell in row.iter() {
                    println!("  \"{:#}\",", cell.into_repr().to_string());
                }
                println!(" ],");
            }
            println!("];");
        }
        Args::InitStore { tree_path, notes_path } => {
            let tree = MerkleTreeStore::default();
            let notes = Notes::default();

            serialize_to_file(&tree, &tree_path);
            serialize_to_file(&notes, &notes_path);
        }
        Args::Deposit { tree_path, notes_path, identifier, amount } => {
            let rng = &mut StdRng::from_entropy();
            let secret = Fr::rand(rng);
            let identifier = identifier_to_fr(&identifier);
            let amount = str_to_amount(&amount);

            // load merkle tree
            let tree_store: MerkleTreeStore = deserialize_from_file(&tree_path);
            let params = FieldHasherGeneratorInstance::generate();
            let mut merkle_tree = tree_store
                .into_merkle_tree(NativeFieldHasherInstance::new(&params))
                .unwrap_or_else(|e| panic!("unable to create merkle tree: {e}"));

            // load notes
            let mut notes: Notes = deserialize_from_file(&notes_path);

            // handle deposit
            let mut hasher = NativeFieldHasherInstance::new(&params);
            let commitment = hasher.hash(&mut (), &[secret])
                .unwrap_or_else(|e| panic!("unable to hash: {e}"));
            let leaf_hash = hasher.hash(&mut (), &[identifier, amount.into(), commitment])
                .unwrap_or_else(|e| panic!("unable to hash: {e}"));
            let leaf_index = merkle_tree
                .add_leaf(leaf_hash)
                .unwrap_or_else(|e| panic!("unable to add leaf: {e}"));
            
            // update merkle tree store
            let tree_store: MerkleTreeStore = merkle_tree.into();
            serialize_to_file(&tree_store, &tree_path);
            // update notes store
            notes.0.push(Note {
                leaf_index,
                identifier,
                amount,
                secret,
            });
            serialize_to_file(&notes, &notes_path);
        }
        Args::ListNotes { notes_path } => {
            let notes: Notes = deserialize_from_file(&notes_path);
            for (i, note) in notes.0.iter().enumerate() {
                let identifier = note.identifier.into_repr().to_bytes_le();
                println!("note {i}:");
                println!("  leaf index = {}", note.leaf_index);
                println!("  identifier = {}", Address::from_slice(&identifier[..20]));
                println!("  amount = {}", note.amount);
            }
        }
        Args::ProveWithdraw {
            ck_path,
            cvk_path,
            pk_path,
            epk_path,
            vk_path,
            tree_path,
            notes_path,
            note_indexes,
            identifiers_set,
            identifier,
            amount,
        } => {
            assert_eq!(note_indexes.len(), NOTE_INPUTS, "unmatched size of input notes");
            assert!(identifiers_set.len() <= TABLE_SIZE, "identifiers set too large");
            
            let rng = &mut StdRng::from_entropy();
            let indexes: [_; NOTE_INPUTS] = array_init(|i| note_indexes[i]);
            let identifiers_set = identifiers_set
                .iter()
                .map(|i| identifier_to_fr(i))
                .collect::<Vec<_>>();
            let new_secret = Fr::rand(rng);
            let new_identifier = identifier_to_fr(&identifier);
            let withdraw_amount = str_to_amount(&amount);
            
            let params = FieldHasherGeneratorInstance::generate();
            // deserialize merkle tree
            let tree_store: MerkleTreeStore = deserialize_from_file(&tree_path);
            let mut merkle_tree = tree_store
                .into_merkle_tree(NativeFieldHasherInstance::new(&params))
                .unwrap_or_else(|e| panic!("unable to create merkle tree: {e}"));

            // deserialize notes
            let mut notes: Notes = deserialize_from_file(&notes_path);
            let using_notes = map_array_init(&indexes, |&index| {
                notes.0.get(index).unwrap_or_else(|| panic!("invalid note index: {index}")).clone()
            });

            // build circuits
            let root = merkle_tree.root();
            let withdraw_circuit = WithdrawCircuit {
                hasher: FieldHasherInstance::new(&params),
                secrets: map_array_init(&using_notes, |note| note.secret),
                identifiers: map_array_init(&using_notes, |note| note.identifier),
                amount_inputs: map_array_init(&using_notes, |note| note.amount),
                poe_circuits: map_array_init(&using_notes, |note| PoECircuit {
                    leaf_index: note.leaf_index,
                    path_elements: merkle_tree.merkle_path(note.leaf_index),
                }),
                root,
                new_secret,
                new_identifier,
                withdraw_amount,
                _p: PhantomData,
            };

            // insert new leaf in merkle tree
            let mut hasher = NativeFieldHasherInstance::new(&params);
            let amount_out = using_notes
                .iter()
                .map(|note| note.amount)
                .sum::<Amount>()
                .sub(withdraw_amount);
            let nullifiers = using_notes
                .iter()
                .map(|n| {
                    let secret_inv = n.secret.inverse().unwrap();
                    hasher.hash(&mut (), &[secret_inv]).unwrap_or_else(|e| panic!("unable to hash: {e}"))
                })
                .collect::<Vec<_>>();
            let commitment = hasher.hash(&mut (), &[new_secret])
                .unwrap_or_else(|e| panic!("unable to hash: {e}"));
            let new_leaf_hash = hasher.hash(&mut (), &[new_identifier, amount_out.into(), commitment])
                .unwrap_or_else(|e| panic!("unable to hash: {e}"));
            // set public inputs
            let mut public_inputs = Vec::with_capacity(4 + NOTE_INPUTS);
            public_inputs.push(root);
            public_inputs.extend(nullifiers);
            public_inputs.push(withdraw_amount.into());
            public_inputs.push(new_identifier);
            public_inputs.push(new_leaf_hash);

            // deserialize keys
            let ck: <CommitmentScheme as PolynomialCommitment<_, _>>::CommitterKey =
                deserialize_from_file(&ck_path);
            let cvk: <CommitmentScheme as PolynomialCommitment<_, _>>::VerifierKey =
                deserialize_from_file(&cvk_path);
            let pk: ProverKey<Fr> = deserialize_from_file(&pk_path);
            let epk: Option<ExtendedProverKey<Fr>> = epk_path
                .map(|path| deserialize_from_file(&path));
            let vk: VerifierKey<Fr, CommitmentScheme> = deserialize_from_file(&vk_path);

            // prove
            println!("start proving...");
            let proof = ZKTPlonkInstance::prove(
                &ck,
                &pk,
                epk.map(Rc::new),
                &vk,
                identifiers_set,
                withdraw_circuit,
                rng,
            ).unwrap_or_else(|e| panic!("snark prove failed: {e}"));
            println!("proving finished");

            // verify
            println!("start verifying...");
            ZKTPlonkInstance::verify(&cvk, &vk, &proof, &public_inputs)
                .unwrap_or_else(|e| panic!("snark verify failed: {e}"));
            println!("verifying finished");

            let new_leaf_index = merkle_tree
                .add_leaf(new_leaf_hash)
                .unwrap_or_else(|e| panic!("unable to add leaf: {e}"));
            let tree_store: MerkleTreeStore = merkle_tree.into();
            serialize_to_file(&tree_store, &tree_path);

            // update notes
            for note in using_notes {
                notes.0.retain(|n| n.leaf_index != note.leaf_index);
            }
            notes.0.push(Note {
                leaf_index: new_leaf_index,
                identifier: new_identifier,
                amount: amount_out,
                secret: new_secret,
            });
            serialize_to_file(&notes, &notes_path);
        }
    }
}

fn identifier_to_fr(identifier: &str) -> Fr {
    let identifier = Address::from_str(&identifier)
        .unwrap_or_else(|e| panic!("invalid identifier: {e}"))
        .to_fixed_bytes();
    let repr = BigUint::from_bytes_le(&identifier).try_into().unwrap_or_else(|_| {
        panic!("unable to convert BigUint to PrimeField")
    });
    Fr::from_repr(repr).unwrap_or_else(|| {
        panic!("unable to convert BigUint to PrimeField")
    })
}

fn str_to_amount(amount: &str) -> Amount {
    u64::from_str(amount).unwrap_or_else(|_| panic!("invalid amount: {}", amount))
}