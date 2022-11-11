// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! This module holds the components needed in the Constraint System.
//!
//! The two components used are Variables and Wires.

use ark_ff::Field;

/// The value is a reference to the actual value that was added to the
/// constraint system
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Variable(pub(crate) Option<usize>);

#[derive(derivative::Derivative)]
#[derivative(Debug)]
///
pub struct VariableMap<F: Field>(Vec<F>);

impl<F: Field> VariableMap<F> {
    ///
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }

    ///
    pub(crate) fn with_capacity(size: usize) -> Self {
        Self(Vec::with_capacity(size))
    }

    ///
    pub fn assign_variable(&mut self, value: F) -> Variable {
        let var = Variable(Some(self.0.len()));
        self.0.push(value);

        var
    }

    ///
    pub fn value_of_var(&self, var: Variable) -> F {
        if let Some(i) = var.0 {
            self.0[i]
        } else {
            F::zero()
        }
    }
}