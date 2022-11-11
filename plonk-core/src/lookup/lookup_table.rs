// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use std::collections::BTreeMap;
use ark_ff::{Field, FftField};
use ark_poly::EvaluationDomain;
use ark_poly::univariate::DensePolynomial;

use crate::error::Error;
use crate::lookup::MultiSet;
use crate::util::lc;

///
pub trait CustomTable<F: Field> {
    ///
    type DataType: Clone;

    ///
    const FROM_OUT: bool;

    ///
    fn selector() -> F;

    ///
    fn convert(value: Self::DataType) -> F;

    ///
    fn output(_: Self::DataType, _: Self::DataType) -> Self::DataType {
        unimplemented!("output function is not implemented");
    }

    ///
    fn collect_a_inputs() -> Vec<Self::DataType> {
        unimplemented!("collect a inputs function is not implemented");
    }

    ///
    fn collect_b_inputs() -> Vec<Self::DataType> {
        unimplemented!("collect b inputs function is not implemented");
    }

    ///
    fn collect_outputs() -> Vec<Self::DataType> {
        unimplemented!("collect outputs function is not implemented");
    }

    ///
    fn row_from_input(a: Self::DataType, b: Self::DataType) -> (F, F, F) {
        (
            Self::convert(a.clone()),
            Self::convert(b.clone()),
            Self::convert(Self::output(a, b)),
        )
    }

    ///
    fn row_from_output(c: Self::DataType) -> (F, F, F) {
        (F::zero(), F::zero(), Self::convert(c))
    }

    ///
    fn collect_rows() -> Vec<(F, F, F)> {
        if Self::FROM_OUT {
            Self::collect_outputs().into_iter().map(Self::row_from_output).collect()
        } else {
            Self::collect_a_inputs()
                .into_iter()
                .zip(Self::collect_b_inputs())
                .map(|(a, b)| {
                    Self::row_from_input(a, b)
                })
                .collect()
        }
    }
}

///
#[macro_export]
macro_rules! impl_range_table {
    ($table:ident, $tp:ty, $sel:expr) => {
        pub struct $table;

        impl<F: Field> CustomTable<F> for $table {
            type DataType = $tp;

            const FROM_OUT: bool = true;

            fn selector() -> F {
                F::from($sel)
            }

            fn convert(value: Self::DataType) -> F {
                F::from(value)
            }

            fn collect_outputs() -> Vec<Self::DataType> {
                (0..=<$tp>::MAX).collect()
            }
        }
    };
}

///
#[macro_export]
macro_rules! impl_logic_operation_table {
    ($table:ident, $tp:ty, $out:ident, $sel:expr) => {
        pub struct $table;

        impl<F: Field> CustomTable<F> for $table {
            type DataType = $tp;

            const FROM_OUT: bool = false;

            fn selector() -> F {
                F::from($sel)
            }

            fn convert(value: Self::DataType) -> F {
                F::from(value)
            }

            fn output(left: Self::DataType, right: Self::DataType) -> Self::DataType {
                $out(left, right)
            }

            fn collect_a_inputs() -> Vec<Self::DataType> {
                (0..=<$tp>::MAX).collect()
            }

            fn collect_b_inputs() -> Vec<Self::DataType> {
                (0..=<$tp>::MAX).collect()
            }
        }
    };
}

impl_range_table!(U8RangeTable, u8, 1u64);
impl_range_table!(U16RangeTable, u16, 2u64);

#[inline]
fn and(a: u8, b: u8) -> u8 { a & b }
impl_logic_operation_table!(U8AndTable, u8, and, 3u64);

#[inline]
fn or(a: u8, b: u8) -> u8 { a | b }
impl_logic_operation_table!(U8OrTable, u8, or, 4u64);

#[inline]
fn xor(a: u8, b: u8) -> u8 { a ^ b }
impl_logic_operation_table!(U8XorTable, u8, xor, 5u64);

#[inline]
fn and_not(a: u8, b: u8) -> u8 { a & (!b) }
impl_logic_operation_table!(U8AndNotTable, u8, and_not, 6u64);

/// This struct is a table, contaning a vector, of arity 4 where each of the
/// values is a scalar. The elements of the table are determined by the function
/// g for g(x,y), used to compute tuples.
///
/// This struct will be used to determine the outputs of gates within arithmetic
/// circuits.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LookupTable<F: Field>(BTreeMap<F, Vec<(F, F, F)>>);

impl<F: Field> LookupTable<F> {
    /// Create a new, empty Plookup table, with arity 4.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    ///
    pub fn selectors(&self) -> usize {
        self.0.len()
    }

    /// Returns the length of the `LookupTable` vector.
    pub fn size(&self) -> usize {
        self.0.iter().map(|(_, rows)| rows.len()).sum()
    }

    ///
    pub fn add_custom_table<T>(&mut self) -> Result<&mut Self, Error>
    where
        T: CustomTable<F>,
    {
        let sel = T::selector();
        let rows = T::collect_rows();

        if self.0.insert(sel, rows).is_some() {
            Err(Error::TableRepeated(std::any::type_name::<T>()))
        } else {
            Ok(self)
        }
    }

    /// Takes in a table, which is a vector of slices containing
    /// 4 elements, and turns them into 3 distinct multisets for
    /// a, b, c.
    fn to_multisets(self) -> (
        MultiSet<F>,
        MultiSet<F>,
        MultiSet<F>,
        MultiSet<F>,
    ) {
        let mut result = (
            MultiSet::with_capacity(self.size()),
            MultiSet::with_capacity(self.size()),
            MultiSet::with_capacity(self.size()),
            MultiSet::with_capacity(self.size()),
        );
        self.0.into_iter().for_each(|(sel, rows)| {
            rows.into_iter().for_each(|row| {
                result.0.push(row.0);
                result.1.push(row.1);
                result.2.push(row.2);
                result.3.push(sel);
            });
        });
        
        result
    }

    ///
    pub(crate) fn compress_to_multiset(self, n: usize, zeta: F) -> MultiSet<F> {
        let (t1, t2, t3, t4) = self.to_multisets();
        let mut t = lc(&[t1, t2, t3, t4], zeta);
        t.pad(n);
        
        t
    }

    ///
    pub(crate) fn selector_polynomial<D>(&self, domain: &D) -> DensePolynomial<F>
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        let sel: MultiSet<F> = self.0.iter().map(|(sel, _)| *sel).collect();
        sel.to_polynomial(domain)
    }

    ///
    pub(crate) fn to_polynomials<D>(
        self,
        domain: &D,
    ) -> (
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
        DensePolynomial<F>,
    )
    where
        F: FftField,
        D: EvaluationDomain<F>,
    {
        let (t1, t2, t3, t4) = self.to_multisets();

        (
            t1.to_polynomial(domain),
            t2.to_polynomial(domain),
            t3.to_polynomial(domain),
            t4.to_polynomial(domain)
        )
    }

    /// Attempts to find an output value, given two input values, by querying
    /// the lookup table. The final wire holds the index of the table. The
    /// element must be predetermined to be between -1 and 2 depending on
    /// the type of table used. If the element does not exist, it will
    /// return an error.
    pub(crate) fn lookup<T: CustomTable<F>>(&self, a: &F, b: &F) -> Result<F, Error> {
        let (_, _, r3) = self
            .0
            .get(&T::selector())
            .ok_or(Error::TableNotRegistered)?
            .iter()
            .find(|(r1, r2, _)| r1 == a && r2 == b)
            .ok_or(Error::ElementNotIndexed)?;

        Ok(*r3)
    }
}

// #[cfg(test)]
// mod test {
//     use super::*;
//     use crate::batch_field_test;
//     use ark_bls12_377::Fr as Bls12_377_scalar_field;
//     use ark_bls12_381::Fr as Bls12_381_scalar_field;

//     fn test_add_table<F>()
//     where
//         F: Field,
//     {
//         let n = 4;
//         let table = LookupTable::add_table(0, n);
//         // Create an identical matrix, but with std numbers.
//         // This way, we can also do the modulo operation, and properly
//         // check all results.
//         let mut i = 0;
//         let p = 2u64.pow(n as u32);
//         (0..p).for_each(|a| {
//             (0..p).for_each(|b| {
//                 let c = (a + b) % p;
//                 assert_eq!(F::from(c), table.0[i][2]);
//                 i += 1;
//             })
//         });
//         assert_eq!(
//             table.0.len() as u64,
//             2u64.pow(n as u32) * 2u64.pow(n as u32)
//         );
//     }

//     fn test_xor_table<F>()
//     where
//         F: Field,
//     {
//         let n = 4;
//         let table = LookupTable::xor_table(0, n);
//         let mut i = 0;
//         let p = 2u64.pow(n as u32);
//         (0..p).for_each(|a| {
//             (0..p).for_each(|b| {
//                 let c = a ^ b;
//                 assert_eq!(F::from(c), table.0[i][2]);
//                 i += 1;
//             })
//         });
//         assert_eq!(
//             table.0.len() as u64,
//             2u64.pow(n as u32) * 2u64.pow(n as u32)
//         );
//     }

//     fn test_mul_table<F>()
//     where
//         F: Field,
//     {
//         let n = 4;
//         let table = LookupTable::mul_table(0, n);
//         let mut i = 0;
//         let p = 2u64.pow(n as u32);
//         (0..p).for_each(|a| {
//             (0..p).for_each(|b| {
//                 let c = (a * b) % p;
//                 assert_eq!(F::from(c), table.0[i][2]);
//                 i += 1;
//             })
//         });
//         assert_eq!(
//             table.0.len() as u64,
//             2u64.pow(n as u32) * 2u64.pow(n as u32)
//         );
//     }

//     fn test_lookup_arity_3<F>()
//     where
//         F: Field,
//     {
//         let add_table = LookupTable::add_table(0, 3);
//         assert!(add_table
//             .lookup(F::from(2u32), F::from(3u32), F::from(0u32))
//             .is_ok());
//         let output = add_table.0[1][0] + add_table.0[1][1];
//         assert_eq!(output, F::one());
//         let second_output = add_table.0[12][0] + add_table.0[12][1];
//         assert_eq!(second_output, F::from(5u32));
//     }

//     fn test_missing_lookup_value<F>()
//     where
//         F: Field,
//     {
//         let xor_table = LookupTable::xor_table(0, 5);
//         assert!(xor_table
//             .lookup(F::from(17u32), F::from(367u32), F::from(0u32))
//             .is_err());
//     }

//     fn test_concatenated_table<F: ark_ff::PrimeField>()
//     where
//         F: Field,
//     {
//         use ark_ff::BigInteger;
//         let mut table = LookupTable::<F>::new();
//         table.insert_multi_xor(0, 5);
//         table.insert_multi_add(4, 7);
//         assert_eq!(table.0.last().unwrap()[2], F::from(126u64));
//         let xor: F = F::from_repr(BigInteger::from_bits_le(
//             table.0[36][0]
//                 .into_repr()
//                 .to_bits_le()
//                 .iter()
//                 .zip(table.0[36][1].into_repr().to_bits_le().iter())
//                 .map(|(l, r)| l ^ r)
//                 .collect::<Vec<_>>()
//                 .as_slice(),
//         ))
//         .unwrap();

//         assert_eq!(xor, F::from(5u64));
//     }

//     // Bls12-381 tests
//     batch_field_test!(
//         [
//             test_add_table,
//             test_xor_table,
//             test_mul_table,
//             test_lookup_arity_3,
//             test_missing_lookup_value,
//             test_concatenated_table
//         ],
//         [] => Bls12_381_scalar_field
//     );

//     // Bls12-377 tests
//     batch_field_test!(
//         [
//             test_add_table,
//             test_xor_table,
//             test_mul_table,
//             test_lookup_arity_3,
//             test_missing_lookup_value,
//             test_concatenated_table
//         ],
//         [] => Bls12_377_scalar_field
//     );
// }
