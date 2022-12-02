// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use alloc::collections::BTreeMap;
use ark_ff::{Field, FftField};
use ark_poly::EvaluationDomain;
use ark_poly::univariate::DensePolynomial;

use crate::util::lc;

use super::*;

/// This struct is a table, contaning a vector, of arity 4 where each of the
/// values is a scalar. The elements of the table are determined by the function
/// g for g(x,y), used to compute tuples.
///
/// This struct will be used to determine the outputs of gates within arithmetic
/// circuits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LookupTable<F: Field>(BTreeMap<&'static str, Vec<[F; 3]>>);

impl<F: Field> LookupTable<F> {
    /// Create a new, empty Plookup table, with arity 4.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    ///
    pub fn tables(&self) -> usize {
        self.0.len()
    }

    /// Returns the length of the `LookupTable` vector.
    pub fn size(&self) -> usize {
        self.0.iter().map(|(_, r)| r.len()).sum()
    }

    ///
    pub fn contains_table<T: CustomTable<F>>(&mut self) -> bool {
        let name = std::any::type_name::<T>();
        self.0.contains_key(name)
    }

    ///
    pub fn register_table<T: CustomTable<F>>(&mut self) -> &mut Self {
        let name = std::any::type_name::<T>();
        if !self.contains_table::<T>() {
            let rows = T::collect_rows();
            self.0.insert(name, rows);
        }

        self
    }

    ///
    pub fn contains<T: CustomSet<F>>(&self, x: &F) {
        let name = std::any::type_name::<T>();
        self
            .0
            .get(name)
            .unwrap_or_else(|| panic!("{} is not registered", name))
            .iter()
            .find(|row| &row[0] == x)
            .unwrap_or_else(|| panic!("element not found in {}", name));
    }

    ///
    pub fn lookup_1d<T: Custom1DMap<F>>(&self, x: &F) -> F {
        let name = std::any::type_name::<T>();
        let row = self
            .0
            .get(name)
            .unwrap_or_else(|| panic!("{} is not registered", name))
            .iter()
            .find(|row| &row[0] == x)
            .unwrap_or_else(|| panic!("element not found in {}", name));

        row[1]
    }

    /// Attempts to find an output value, given two input values, by querying
    /// the lookup table. The final wire holds the index of the table. The
    /// element must be predetermined to be between -1 and 2 depending on
    /// the type of table used. If the element does not exist, it will
    /// return an error.
    pub fn lookup_2d<T: Custom2DMap<F>>(&self, x: &F, y: &F) -> F {
        let name = std::any::type_name::<T>();
        let row = self
            .0
            .get(name)
            .unwrap_or_else(|| panic!("{} is not registered", name))
            .iter()
            .find(|row| &row[0] == x && &row[1] == y)
            .unwrap_or_else(|| panic!("elements not found in {}", name));

        row[2]
    }

    /// Takes in a table, which is a vector of slices containing
    /// 4 elements, and turns them into 3 distinct multisets for
    /// a, b, c.
    fn into_multisets(self) -> Vec<MultiSet<F>> {
        let mut msets = vec![MultiSet::with_capacity(self.size()); 4];
        for (i, (_, rows)) in self.0.into_iter().enumerate() {
            let id = i as u64;
            for row in rows {
                msets[0].push(row[0]);
                msets[1].push(row[1]);
                msets[2].push(row[2]);
                msets[3].push(id.into());
            }
        }
        
        msets
    }

    ///
    pub(crate) fn compress_to_multiset(self, n: usize, zeta: F) -> MultiSet<F> {
        let msets = self.into_multisets();
        let mut t = lc(&msets, zeta);
        t.pad(n);
        
        t
    }

    ///
    pub(crate) fn selector_polynomial<D>(&self, domain: &D) -> DensePolynomial<F>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        let sel: MultiSet<F> = (0..self.tables() as u64).into_iter().map(F::from).collect();
        sel.into_polynomial(domain)
    }

    ///
    pub(crate) fn into_polynomials<D>(
        self,
        domain: &D,
    ) -> Vec<DensePolynomial<F>>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        self.into_multisets()
            .into_iter()
            .map(|t| t.into_polynomial(domain))
            .collect()
    }
}

#[cfg(test)]
mod test {
    use ark_ff::Field;
    use ark_std::test_rng;
    use ark_bn254::Bn254;

    use crate::{batch_test_field, impl_custom_table};

    use super::*;

    pub struct DummySet;

    impl<F: Field> CustomSet<F> for DummySet {
        type Element = F;

        fn collect_elements() -> Vec<Self::Element> {
            let rng = &mut test_rng();
            (0..8).into_iter().map(|_| F::rand(rng)).collect()
        }
    }

    impl_custom_table!(DummySet, CustomSet);

    pub struct Dummy1DMap;

    impl<F: Field> Custom1DMap<F> for Dummy1DMap {
        type X = F;
        type Y = F;

        fn lookup(x: Self::X) -> Self::Y {
            x.square()
        }

        fn collect_x_axis() -> Vec<Self::X> {
            let rng = &mut test_rng();
            (0..8).into_iter().map(|_| F::rand(rng)).collect()
        }
    }

    impl_custom_table!(Dummy1DMap, Custom1DMap);

    pub struct Dummy2DMap;

    impl<F: Field> Custom2DMap<F> for Dummy2DMap {
        type X = F;
        type Y = F;
        type Z = F;

        fn lookup(x: Self::X, y: Self::Y) -> Self::Z {
            x * y
        }

        fn collect_x_axis() -> Vec<Self::X> {
            let rng = &mut test_rng();
            (0..8).into_iter().map(|_| F::rand(rng)).collect()
        }

        fn collect_y_axis() -> Vec<Self::Y> {
            let rng = &mut test_rng();
            (0..8).into_iter().map(|_| F::rand(rng)).collect()
        }
    }

    impl_custom_table!(Dummy2DMap, Custom2DMap);

    fn test_register_tables<F: Field>() {
        let mut table = LookupTable::<F>::new();
    
        table.register_table::<DummySet>();
        table.register_table::<Dummy1DMap>();
        table.register_table::<Dummy2DMap>();

        assert_eq!(table.tables(), 3);
        assert_eq!(table.size(), 8 + 8 + 64);
    }

    fn test_contains<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<DummySet>();

        DummySet::collect_elements()
            .into_iter()
            .for_each(|e| table.contains::<DummySet>(&e));
    }

    fn test_contains_failed<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<DummySet>();

        table.contains::<DummySet>(&F::zero());
    }

    fn test_lookup_1d<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<Dummy1DMap>();

        Dummy1DMap::collect_x_axis()
            .into_iter()
            .for_each(|x| {
                table.lookup_1d::<Dummy1DMap>(&x);
            });
    }

    fn test_lookup_1d_failed<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<Dummy1DMap>();

        table.lookup_1d::<Dummy1DMap>(&F::zero());
    }

    fn test_lookup_2d<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<Dummy2DMap>();

        Dummy2DMap::collect_x_axis()
            .into_iter()
            .zip(Dummy2DMap::collect_y_axis())
            .for_each(|(x, y)| {
                table.lookup_2d::<Dummy2DMap>(&x, &y);
            });
    }

    fn test_lookup_2d_failed<F: Field>() {
        let mut table = LookupTable::<F>::new();
        table.register_table::<Dummy2DMap>();

        table.lookup_2d::<Dummy2DMap>(&F::zero(), &F::zero());
    }

    batch_test_field!(
        Bn254,
        [
            test_register_tables,
            test_contains,
            test_lookup_1d,
            test_lookup_2d
        ],
        [
            test_contains_failed,
            test_lookup_1d_failed,
            test_lookup_2d_failed
        ]
    );
}
