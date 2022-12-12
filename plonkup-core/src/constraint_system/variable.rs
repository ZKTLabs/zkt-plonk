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
pub enum Variable {
    ///
    Zero,
    ///
    One,
    ///
    Var(usize),
}

impl Variable {
    ///
    pub fn linear_transform<F: Field>(
        self,
        coeff: F,
        offset: F,
    ) -> LTVariable<F> {
        LTVariable {
            var: self,
            coeff,
            offset,
        }
    }
}

///
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct LTVariable<F: Field> {
    ///
    pub var: Variable,
    ///
    pub coeff: F,
    ///
    pub offset: F,
}

impl<F: Field> From<Variable> for LTVariable<F> {
    fn from(var: Variable) -> Self {
        Self {
            var,
            coeff: F::one(),
            offset: F::zero(),
        }
    }
}

impl<F: Field> LTVariable<F> {
    ///
    pub fn linear_transform(&self, coeff: F, offset: F) -> Self {
        let coeff = self.coeff * coeff;
        let offset = self.offset * coeff + offset;
        
        Self {
            var: self.var,
            coeff,
            offset,
        }
    }
}

#[derive(derivative::Derivative)]
#[derivative(Debug)]
///
pub struct VariableMap<F: Field> {
    map: Vec<F>,
    #[cfg(feature = "trace")]
    backtrace: Vec<backtrace::Backtrace>,
}

impl<F: Field> VariableMap<F> {
    ///
    pub(crate) fn new() -> Self {
        Self {
            map: Vec::new(),
            #[cfg(feature = "trace")]
            backtrace: Vec::new(),
        }
    }

    ///
    pub(crate) fn with_capacity(size: usize) -> Self {
        Self {
            map: Vec::with_capacity(size),
            #[cfg(feature = "trace")]
            backtrace: Vec::with_capacity(size),
        }
    }

    ///
    pub fn assign_variable(&mut self, value: F) -> Variable {
        if value.is_zero() {
            Variable::Zero
        } else if value.is_one() {
            Variable::One
        } else {
            let var = Variable::Var(self.map.len());
            self.map.push(value);
            #[cfg(feature = "trace")]
            {
                let backtrace = backtrace::Backtrace::new_unresolved();
                self.backtrace.push(backtrace);
            }

            var
        }
    }

    ///
    pub fn value_of_var(&self, var: Variable) -> F {
        match var {
            Variable::Var(i) => self.map[i],
            Variable::Zero => F::zero(),
            Variable::One => F::one(),
        }
    }

    ///
    pub fn value_of_lt_var(&self, lt_var: &LTVariable<F>) -> F {
        let value = match lt_var.var {
            Variable::Var(i) => self.map[i],
            Variable::Zero => F::zero(),
            Variable::One => F::one(),
        };

        value * lt_var.coeff + lt_var.offset
    }

    #[cfg(feature = "trace")]
    pub(super) fn backtrace_of_var(&self, var: Variable) -> Option<backtrace::Backtrace> {
        match var {
            Variable::Var(i) => Some(self.backtrace[i].clone()),
            Variable::Zero => None,
            Variable::One => None,
        }
    }
}