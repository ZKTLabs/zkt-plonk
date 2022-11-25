// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This is an extension over the [Merlin Transcript](Transcript) which adds a
//! few extra functionalities.

use ark_ff::{Field, PrimeField};
use ark_poly_commit::PCCommitment;
use merlin::Transcript;

/// Transcript adds an abstraction over the Merlin transcript
/// For convenience
pub trait TranscriptProtocol<F, PC>
where
    F: Field,
    PC: PCCommitment + 'static,
{
    ///
    fn new(label: &'static str) -> Self;

    ///
    fn append_u64(&mut self, label: &'static str, item: u64);

    ///
    fn append_scalar(&mut self, label: &'static str, item: &F);

    ///
    fn append_scalars<'a, I>(&mut self, label: &'static str, items: I)
    where
        I: IntoIterator<Item = &'a F>;

    ///
    fn append_commitment(&mut self, label: &'static str, item: &PC);

    ///
    fn append_commitments<'a, I>(&mut self, label: &'static str, items: I)
    where
        I: IntoIterator<Item = &'a PC>;

    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static str) -> F;
}

///
#[derive(Clone)]
pub struct MerlinTranscript(Transcript);

impl<F, PC> TranscriptProtocol<F, PC> for MerlinTranscript
where
    F: PrimeField,
    PC: PCCommitment + 'static,
{
    fn new(label: &'static str) -> Self {
        Self(Transcript::new(label.as_bytes()))
    }

    fn append_u64(&mut self, label: &'static str, item: u64) {
        self.0.append_u64(label.as_bytes(), item)
    }

    fn append_scalar(&mut self, label: &'static str, item: &F) {
        let mut bytes = Vec::new();
        item.write(&mut bytes).expect("F can not convert to bytes");

        self.0.append_message(label.as_bytes(), &bytes)
    }

    fn append_scalars<'a, I>(&mut self, label: &'static str, items: I)
    where
        I: IntoIterator<Item = &'a F>
    {
        let mut bytes = Vec::new();
        for item in items {
            item.write(&mut bytes).expect("F can not convert to bytes");
        }

        self.0.append_message(label.as_bytes(), &bytes)
    }

    fn append_commitment(&mut self, label: &'static str, item: &PC) {
        let mut bytes = Vec::new();
        item.write(&mut bytes).expect("PC can not convert to bytes");

        self.0.append_message(label.as_bytes(), &bytes)
    }

    fn append_commitments<'a, I>(&mut self, label: &'static str, items: I)
    where
        I: IntoIterator<Item = &'a PC>
    {
        let mut bytes = Vec::new();
        for item in items {
            item.write(&mut bytes).expect("F can not convert to bytes");
        }

        self.0.append_message(label.as_bytes(), &bytes)
    }

    fn challenge_scalar(&mut self, label: &'static str) -> F {
        let mut bytes = Vec::new();
        self.0.challenge_bytes(label.as_bytes(), &mut bytes);

        F::from_be_bytes_mod_order(&bytes)
    }
} 
