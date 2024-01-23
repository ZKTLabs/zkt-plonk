// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::Field;
use indexmap::IndexSet;

use super::*;

/// This struct is a table, contaning a vector, of arity 4 where each of the
/// values is a scalar. The elements of the table are determined by the function
/// g for g(x,y), used to compute tuples.
///
/// This struct will be used to determine the outputs of gates within arithmetic
/// circuits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LookupTable<F: Field>(pub IndexSet<F>);

#[allow(dead_code)]
impl<F: Field> LookupTable<F> {
    /// Create a new, empty Plookup table
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn with_capacity(n: usize) -> Self {
        Self(IndexSet::with_capacity(n))
    }

    /// Returns the length of the `LookupTable` set.
    pub fn size(&self) -> usize {
        self.0.len()
    }

    ///
    pub fn contains(&self, entry: &F) {
        self.0.get(entry).unwrap_or_else(|| panic!("element not found in table"));
    }

    ///
    pub(crate) fn masks(&self, n: usize) -> Vec<F> {
        let size = self.size();
        assert!(size < n, "table size is equal or larger than n");

        let mut evals = vec![F::zero(); size];
        evals.resize(n, F::one());
        evals
    }

    /// Takes in a table, which is a vector of slices containing all elements,
    /// turns them into multiset for c and extends the length to `n`, 
    pub(crate) fn into_multiset(self, n: usize) -> MultiSet<F> {
        let mut t = MultiSet::from_iter(self.0.into_iter());
        assert!(t.len() < n, "table size is equal or larger than n");

        t.pad_with_zero(n);
        t
    }
}

impl<F: Field, I: IntoIterator<Item = F>> From<I> for LookupTable<F> {
    fn from(iter: I) -> Self {
        LookupTable(IndexSet::from_iter(iter))
    }
}

// impl<'a, F: Field, I: IntoIterator<Item = &'a F>> From<I> for LookupTable<F> {
//     fn from(iter: I) -> Self {
//         LookupTable(IndexSet::from_iter(iter))
//     }
// }

// #[cfg(test)]
// mod test {
//     use ark_ff::Field;
//     use ark_std::test_rng;
//     use ark_bn254::Bn254;

//     use crate::{batch_test_field, impl_custom_table};
//     use super::*;

//     pub struct DummySet;

//     impl<F: Field> CustomSet<F> for DummySet {
//         type Element = F;

//         fn contains(_element: Self::Element) -> bool {
//             unimplemented!("not needed for testing")
//         }

//         fn collect_elements() -> Vec<Self::Element> {
//             let rng = &mut test_rng();
//             (0..8).into_iter().map(|_| F::rand(rng)).collect()
//         }
//     }

//     impl_custom_table!(DummySet, CustomSet);

//     pub struct Dummy1DMap;

//     impl<F: Field> Custom1DMap<F> for Dummy1DMap {
//         type X = F;
//         type Y = F;

//         fn lookup(x: Self::X) -> Self::Y {
//             x.square()
//         }

//         fn collect_x_axis() -> Vec<Self::X> {
//             let rng = &mut test_rng();
//             (0..8).into_iter().map(|_| F::rand(rng)).collect()
//         }
//     }

//     impl_custom_table!(Dummy1DMap, Custom1DMap);

//     pub struct Dummy2DMap;

//     impl<F: Field> Custom2DMap<F> for Dummy2DMap {
//         type X = F;
//         type Y = F;
//         type Z = F;

//         fn lookup(x: Self::X, y: Self::Y) -> Self::Z {
//             x * y
//         }

//         fn collect_x_axis() -> Vec<Self::X> {
//             let rng = &mut test_rng();
//             (0..8).into_iter().map(|_| F::rand(rng)).collect()
//         }

//         fn collect_y_axis() -> Vec<Self::Y> {
//             let rng = &mut test_rng();
//             (0..8).into_iter().map(|_| F::rand(rng)).collect()
//         }
//     }

//     impl_custom_table!(Dummy2DMap, Custom2DMap);

//     fn test_register_tables<F: Field>() {
//         let mut table = LookupTable::<F>::new();
    
//         table.register_table::<DummySet>();
//         table.register_table::<Dummy1DMap>();
//         table.register_table::<Dummy2DMap>();

//         assert_eq!(table.tables(), 3);
//         assert_eq!(table.size(), 8 + 8 + 64);
//     }

//     fn test_contains<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<DummySet>();

//         DummySet::collect_elements()
//             .into_iter()
//             .for_each(|e| table.contains::<DummySet>(&e));
//     }

//     fn test_contains_failed<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<DummySet>();

//         table.contains::<DummySet>(&F::zero());
//     }

//     fn test_lookup_1d<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<Dummy1DMap>();

//         Dummy1DMap::collect_x_axis()
//             .into_iter()
//             .for_each(|x| {
//                 table.lookup_1d::<Dummy1DMap>(&x);
//             });
//     }

//     fn test_lookup_1d_failed<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<Dummy1DMap>();

//         table.lookup_1d::<Dummy1DMap>(&F::zero());
//     }

//     fn test_lookup_2d<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<Dummy2DMap>();

//         Dummy2DMap::collect_x_axis()
//             .into_iter()
//             .zip(Dummy2DMap::collect_y_axis())
//             .for_each(|(x, y)| {
//                 table.lookup_2d::<Dummy2DMap>(&x, &y);
//             });
//     }

//     fn test_lookup_2d_failed<F: Field>() {
//         let mut table = LookupTable::<F>::new();
//         table.register_table::<Dummy2DMap>();

//         table.lookup_2d::<Dummy2DMap>(&F::zero(), &F::zero());
//     }

//     batch_test_field!(
//         Bn254,
//         [
//             test_register_tables,
//             test_contains,
//             test_lookup_1d,
//             test_lookup_2d
//         ],
//         [
//             test_contains_failed,
//             test_lookup_1d_failed,
//             test_lookup_2d_failed
//         ]
//     );
// }
