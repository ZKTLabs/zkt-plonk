// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This is an extension over the [Merlin Transcript](Transcript) which adds a
//! few extra functionalities.

use ark_ff::Field;
use ark_poly_commit::PCCommitment;

/// Transcript adds an abstraction over the Merlin transcript
/// For convenience
pub trait TranscriptProtocol<F, PC>
where
    F: Field,
    PC: PCCommitment,
{
    ///
    fn new(label: &str) -> Self;

    ///
    fn append_u64(&mut self, label: &str, item: u64);

    ///
    fn append_scalar(&mut self, label: &str, item: &F);

    ///
    fn append_commitment(&mut self, label: &str, item: &PC);

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &str) -> F;
}

// impl TranscriptProtocol for Transcript {
//     fn append(&mut self, label: &'static [u8], item: &impl CanonicalSerialize) {
//         let mut bytes = Vec::new();
//         item.serialize(&mut bytes).unwrap();
//         self.append_message(label, &bytes)
//     }

//     fn challenge_scalar<F: PrimeField>(&mut self, label: &'static [u8]) -> F {
//         // XXX: review this: assure from_random_bytes returnes a valid Field
//         // element
//         let size = F::size_in_bits() / 8;
//         let mut buf = vec![0u8; size];
//         self.challenge_bytes(label, &mut buf);
//         F::from_random_bytes(&buf).unwrap()
//     }

//     fn circuit_domain_sep(&mut self, n: u64) {
//         self.append_u64(b"circuit_domain_sep", n);
//     }
// }
