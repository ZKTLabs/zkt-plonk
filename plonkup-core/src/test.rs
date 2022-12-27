// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) ZK-GARAGE. All rights reserved.

//! Test Suite

/// Defines a set of tests on a pairing engine / curve combination.
///
/// The set of tests is split in two. The first set between `[]` is for regular
/// tests that should not panic. The second set is for tests that should panic.

///
#[macro_export]
macro_rules! batch_test_field {
    ($engine:ty, [$($test_set:ident),*], [$($test_panic_set:ident),*]) => {
        paste::paste! {
            $(
                #[test]
                #[allow(non_snake_case)]
                fn [< $test_set _on_ $engine>]() {
                    $test_set::<<$engine as ark_ec::PairingEngine>::Fr>()
                }
            )*
            $(
                #[test]
                #[should_panic]
                #[allow(non_snake_case)]
                fn [< $test_panic_set _on_ $engine>]() {
                    $test_panic_set::<<$engine as ark_ec::PairingEngine>::Fr>()
                }
            )*
        }
    }
}

///
#[macro_export]
macro_rules! batch_test_kzg {
    ($engine:ty, [$($test_set:ident),*], [$($test_panic_set:ident),*]) => {
        paste::paste! {
            $(
                #[test]
                #[allow(non_snake_case)]
                fn [< $test_set _with_kzg_on_ $engine>]() {
                    $test_set::<<$engine as ark_ec::PairingEngine>::Fr, crate::commitment::KZG10<$engine>>()
                }
            )*
            $(
                #[test]
                #[should_panic]
                #[allow(non_snake_case)]
                fn [< $test_panic_set _with_kzg_on_ $engine>]() {
                    $test_panic_set::<<$engine as ark_ec::PairingEngine>::Fr, crate::commitment::KZG10<$engine>>()
                }
            )*
        }
    }
}

///
#[macro_export]
macro_rules! batch_test_ipa {
    ($engine:ty, [$($test_set:ident),*], [$($test_panic_set:ident),*]) => {
        paste::paste! {
            $(
                #[test]
                #[allow(non_snake_case)]
                fn [< $test_set _with_ipa_on_ $engine>]() {
                    $test_set::<
                        <$engine as ark_ec::PairingEngine>::Fr,
                        crate::commitment::IPA<<$engine as ark_ec::PairingEngine>::G1Affine, blake2::Blake2s>
                    >()
                }
            )*
            $(
                #[test]
                #[should_panic]
                #[allow(non_snake_case)]
                fn [< $test_panic_set _with_ipa_on_ $engine>]() {
                    $test_panic_set::<
                        <$engine as ark_ec::PairingEngine>::Fr,
                        crate::commitment::IPA<<$engine as ark_ec::PairingEngine>::G1Affine, blake2::Blake2s>
                    >()
                }
            )*
        }
    }
}
