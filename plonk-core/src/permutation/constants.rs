// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-GARAGE. All rights reserved.

//! Constants are used in the permutation argument to generate H cosets.
#![allow(non_snake_case)]

use ark_ff::Field;

#[inline]
pub(crate) fn K1<F: Field>() -> F {
    F::from(7u64)
}

#[inline]
pub(crate) fn K2<F: Field>() -> F {
    F::from(13u64)
}

#[cfg(test)]
mod test {
    use ark_bn254::Bn254;
    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;
    use ark_ff::{FftField, FftParameters};
    use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

    use crate::batch_test_field;
    use super::*;

    /// Check if `cts` generate valid cosets of the roots of
    /// unity subgroup (of `domain_size`) of the field F.
    /// https://hackmd.io/CfFCbA0TTJ6X08vHg0-9_g
    fn test_constants<F: FftField>() {
        // The constants are checked for subgropus H up to 2^MAX_DEGREE size.
        let max_degree = <F::FftParams as FftParameters>::TWO_ADICITY;
        let n = 1u64 << max_degree;
        let domain =
            GeneralEvaluationDomain::<F>::new(n as usize).unwrap();

        // Check K1^domain_size - 1 != 0.
        assert!(!domain.evaluate_vanishing_polynomial(K1()).is_zero());

        // Check that the constant K2 is not in generated cosets K1 * H.
        // (K1 / K2 )^domain_size - 1 != 0.
        let product = K1::<F>() * K2::<F>().inverse().unwrap();
        assert!(!domain.evaluate_vanishing_polynomial(product).is_zero());
    }

    batch_test_field!(
        Bn254,
        [test_constants],
        []
    );

    batch_test_field!(
        Bls12_377,
        [test_constants],
        []
    );

    batch_test_field!(
        Bls12_381,
        [test_constants],
        []
    );
}
