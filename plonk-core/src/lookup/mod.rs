// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! Module containing the lookups.

mod custom;
mod table;
mod multiset;

pub(crate) use multiset::MultiSet;

pub use custom::*;
pub use table::*;

// // #[cfg(test)]
// // mod test {
// //     use super::*;
// //     use crate::batch_test;
// //     use crate::commitment::HomomorphicCommitment;
// //     use crate::lookup::{LookupTable, PreprocessedLookupTable};
// //     use ark_bls12_377::Bls12_377;
// //     use ark_bls12_381::Bls12_381;
// //     use ark_ec::TEModelParameters;
// //     use rand_core::OsRng;

// //     /// This function creates a table and preprocesses it. Then it checks that
// //     /// all table columns are the same length.
// //     fn test_table_preprocessing<F, P, PC>()
// //     where
// //         F: PrimeField,
// //         P: TEModelParameters<BaseField = F>,
// //         PC: HomomorphicCommitment<F>,
// //     {
// //         let pp = PC::setup(32, None, &mut OsRng)
// //             .map_err(to_pc_error::<F, PC>)
// //             .unwrap();
// //         let (_committer_key, _) = PC::trim(&pp, 32, 0, None)
// //             .map_err(to_pc_error::<F, PC>)
// //             .unwrap();

// //         // Commit Key
// //         let (ck, _) = PC::trim(&pp, 32, 0, None)
// //             .map_err(to_pc_error::<F, PC>)
// //             .unwrap();

// //         let mut table: LookupTable<F> = LookupTable::new();

// //         (0..11).for_each(|_a| {
// //             table.insert_xor_row(19u64, 6u64, 64u64);
// //             table.insert_xor_row(4u64, 2u64, 64u64);
// //         });

// //         let preprocessed_table =
// //             PreprocessedLookupTable::<F, PC>::preprocess(&table, &ck, 32)
// //                 .unwrap();

// //         preprocessed_table.t.iter().for_each(|column| {
// //             assert!(preprocessed_table.n as usize == column.0.len());
// //         });
// //     }

// //     // Bls12-381 tests
// //     batch_test!(
// //         [
// //             test_table_preprocessing
// //         ],
// //         [] => (
// //             Bls12_381,
// //             ark_ed_on_bls12_381::EdwardsParameters
// //         )
// //     );

// //     // Bls12-377 tests
// //     batch_test!(
// //         [
// //             test_table_preprocessing
// //         ],
// //         [] => (
// //             Bls12_377,
// //             ark_ed_on_bls12_377::EdwardsParameters
// //         )
// //     );
// // }
