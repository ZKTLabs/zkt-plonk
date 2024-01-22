// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use core::ops::{Add, Mul};
use ark_ff::{FftField, Field};
use ark_poly::{
    EvaluationDomain,
    GeneralEvaluationDomain,
    univariate::DensePolynomial,
    UVPolynomial,
};

/// Returns an iterator over increasing powers of the given `scalar` starting
/// at `0`.
#[inline]
pub fn powers_of<F>(scalar: F) -> impl Iterator<Item = F>
where
    F: Field,
{
    core::iter::successors(Some(F::one()), move |p| Some(*p * scalar))
}

/// Evaluation Domain Extension Trait
pub trait EvaluationDomainExt<F>: EvaluationDomain<F>
where
    F: FftField,
{
    /// Returns the value of `log_2(self.size)`.
    fn log_size_of_group(&self) -> u32;

    /// Returns a fixed generator of the subgroup.
    fn group_gen(&self) -> F;
}

impl<F> EvaluationDomainExt<F> for GeneralEvaluationDomain<F>
where
    F: FftField,
{
    #[inline]
    fn log_size_of_group(&self) -> u32 {
        match self {
            GeneralEvaluationDomain::Radix2(domain) => domain.log_size_of_group,
            GeneralEvaluationDomain::MixedRadix(domain) => {
                domain.log_size_of_group
            }
        }
    }

    #[inline]
    fn group_gen(&self) -> F {
        match self {
            GeneralEvaluationDomain::Radix2(domain) => domain.group_gen,
            GeneralEvaluationDomain::MixedRadix(domain) => domain.group_gen,
        }
    }
}

///
#[inline]
pub(crate) fn poly_from_evals<F, D>(
    domain: &D,
    mut evals: Vec<F>,
) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    domain.ifft_in_place(&mut evals);
    DensePolynomial::from_coefficients_vec(evals)
}

///
#[inline]
pub(crate) fn poly_from_evals_ref<F, D>(
    domain: &D,
    evals: &[F],
) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    DensePolynomial::from_coefficients_vec(domain.ifft(evals))
}

///
#[inline]
pub(crate) fn poly_from_coset_evals<F, D>(
    domain: &D,
    mut evals: Vec<F>,
) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    domain.coset_ifft_in_place(&mut evals);
    DensePolynomial::from_coefficients_vec(evals)
}

///
#[inline]
pub(crate) fn evals_from_poly_ref<F, D>(
    domain: &D,
    poly: &DensePolynomial<F>,
) -> Vec<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    domain.fft(poly)
}

///
#[inline]
pub(crate) fn coset_evals_from_poly<F, D>(
    domain: &D,
    mut poly: DensePolynomial<F>,
) -> Vec<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    domain.coset_fft_in_place(&mut poly.coeffs);
    poly.coeffs
}

///
#[inline]
pub(crate) fn coset_evals_from_poly_ref<F, D>(
    domain: &D,
    poly: &DensePolynomial<F>,
) -> Vec<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    domain.coset_fft(poly)
}

/// Linear combination of a series of values
///
/// For values [v_0, v_1,... v_k] returns:
/// v_0 + challenge * v_1 + ... + challenge^k  * v_k
#[allow(dead_code)]
pub(crate) fn lc<T, F>(values: &[T], challenge: F) -> T
where
    T: Mul<F, Output = T> + Add<T, Output = T> + Clone,
    F: Field,
{
    // Ensure valid challenge
    assert_ne!(challenge, F::zero());
    assert_ne!(challenge, F::one());

    let kth_val = match values.last() {
        Some(val) => val.clone(),
        _ => panic!("At least one value must be provided to compute a linear combination")
    };

    values
        .iter()
        .rev()
        .skip(1)
        .fold(kth_val, |acc, val| acc * challenge + val.clone())
}

/// Lagrange polynomial has the expression:
///
/// ```text
/// L_k(X) = ∏ 0 to (n-1) without k [(x - omega^i) / (omega^k - omega^i)]
/// ```
///
/// with `omega` being the generator of the domain (the `n`th root of unity).
///
/// We use two equalities:
///   1. `∏ 0 to (n-1) without k (omega^k - omega^i) = n / omega^k` NOTE: L'Hôpital Principle
///   2. `∏ 0 to (n-1) without k (x - omega^i) = (x^n - 1) / (x - omega^k)`
/// to obtain the expression:
///
/// ```text
/// L_k(X) = (x^n - 1) * omega^k / n * (x - omega^k)
/// ```
#[inline]
pub(crate) fn compute_lagrange_evaluation<F: Field>(
    n: usize,
    point: F,
    vh_eval: F,
    tau: F,
) -> F {
    let numinator = vh_eval * point;
    let dominator = F::from(n as u64) * (tau - point);
    numinator * dominator.inverse().unwrap()
}

/// Computes first lagrange polynomial over `domain` of `index`.
pub(crate) fn compute_first_lagrange_poly<F, D>(domain: &D) -> DensePolynomial<F>
where
    F: FftField,
    D: EvaluationDomain<F>,
{
    let mut x_evals = vec![F::zero(); domain.size()];
    x_evals[0] = F::one();
    poly_from_evals(domain, x_evals)
}

/// Macro to quickly label polynomials
#[macro_export]
macro_rules! label_polynomial {
    ($poly:expr) => {
        ark_poly_commit::LabeledPolynomial::new(
            stringify!($poly).to_owned(),
            $poly,
            None,
            None,
        )
    };
}

/// Macro to quickly label polynomial commitments
#[macro_export]
macro_rules! label_commitment {
    ($comm:expr) => {
        ark_poly_commit::LabeledCommitment::new(
            stringify!($comm).to_owned(),
            $comm.clone(),
            None,
        )
    };
}

/// Macro to quickly label evaluations
#[macro_export]
macro_rules! label_eval {
    ($eval:expr) => {
        (stringify!($eval).to_owned(), $eval)
    };
}

/// Macro to get appropirate label
#[macro_export]
macro_rules! get_label {
    ($eval:expr) => {
        stringify!($comm).to_owned()
    };
}

///
#[cfg(feature = "parallel")]
#[macro_export]
macro_rules! par_izip {
    // @closure creates a tuple-flattening closure for .map() call. usage:
    // @closure partial_pattern => partial_tuple , rest , of , iterators
    // eg. izip!( @closure ((a, b), c) => (a, b, c) , dd , ee )
    ( @closure $p:pat => $tup:expr ) => {
        |$p| $tup
    };

    // The "b" identifier is a different identifier on each recursion level thanks to hygiene.
    ( @closure $p:pat => ( $($tup:tt)* ) , $_iter:expr $( , $tail:expr )* ) => {
        $crate::par_izip!(@closure ($p, b) => ( $($tup)*, b ) $( , $tail )*)
    };

    // unary
    ($first:expr $(,)*) => {
        rayon::iter::IntoParallelIterator::into_par_iter($first)
    };

    // binary
    ($first:expr, $second:expr $(,)*) => {
        $crate::par_izip!($first)
            .zip($second)
    };

    // n-ary where n > 2
    ( $first:expr $( , $rest:expr )* $(,)* ) => {
        $crate::par_izip!($first)
            $(
                .zip($rest)
            )*
            .map(
                $crate::par_izip!(@closure a => (a) $( , $rest )*)
            )
    };
}

// #[cfg(test)]
// mod test {
//     use crate::batch_field_test;

//     use super::*;
//     use ark_bls12_377::Fr as Bls12_377_scalar_field;
//     use ark_bls12_381::Fr as Bls12_381_scalar_field;
//     use ark_ff::Field;
//     use rand_core::OsRng;

//     fn test_correct_lc<F: Field>() {
//         let n_iter = 10;
//         for _ in 0..n_iter {
//             let a = F::rand(&mut OsRng);
//             let b = F::rand(&mut OsRng);
//             let c = F::rand(&mut OsRng);
//             let d = F::rand(&mut OsRng);
//             let e = F::rand(&mut OsRng);
//             let challenge = F::rand(&mut OsRng);
//             let expected = a
//                 + b * challenge
//                 + c * challenge * challenge
//                 + d * challenge * challenge * challenge
//                 + e * challenge * challenge * challenge * challenge;

//             let result = lc(&[a, b, c, d, e], challenge);
//             assert_eq!(result, expected)
//         }
//     }

//     fn test_incorrect_lc<F: Field>() {
//         let n_iter = 10;
//         for _ in 0..n_iter {
//             let a = F::rand(&mut OsRng);
//             let b = F::rand(&mut OsRng);
//             let c = F::rand(&mut OsRng);
//             let d = F::rand(&mut OsRng);
//             let e = F::rand(&mut OsRng);
//             let challenge = F::rand(&mut OsRng);
//             let expected = F::one()
//                 + a
//                 + b * challenge
//                 + c * challenge * challenge
//                 + d * challenge * challenge * challenge
//                 + e * challenge * challenge * challenge * challenge;

//             let result = lc(&[a, b, c, d, e], challenge);
//             assert_eq!(result, expected)
//         }
//     }
//     batch_field_test!(
//         [
//         test_correct_lc
//         ],
//         [
//         test_incorrect_lc
//         ] => Bls12_381_scalar_field
//     );
//     batch_field_test!(
//         [
//         test_correct_lc
//         ],
//         [
//         test_incorrect_lc
//         ] => Bls12_377_scalar_field
//     );
// }
