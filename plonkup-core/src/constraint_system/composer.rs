// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! A `Composer` could be understood as some sort of Trait that is actually
//! defining some kind of Circuit Builder for PLONK.
//!
//! In that sense, here we have the implementation of the [`ConstraintSystem`]
//! which has been designed in order to provide the maximum amount of
//! performance while having a big scope in utility terms.
//!
//! It allows us not only to build Add and Mul constraints but also to build
//! ECC op. gates, Range checks, Logical gates (Bitwise ops) etc.

use std::borrow::{Borrow, BorrowMut};

use ark_ff::Field;

use crate::{
    permutation::Permutation,
    proof_system::{PublicInputs, PublicPositions},
};

use super::{Variable, VariableMap, LTVariable};

#[derive(Debug, Clone, Copy)]
///
pub struct Selectors<F: Field> {
    q_m: F,
    q_l: F,
    q_r: F,
    q_o: F,
    q_c: F,
    q_lookup: F,
    t_tag: F,
}

impl<F: Field> Selectors<F> {
    ///
    pub fn new_arith() -> Self {
        Self {
            q_m: F::zero(),
            q_l: F::zero(),
            q_r: F::zero(),
            q_o: F::zero(),
            q_c: F::zero(),
            q_lookup: F::zero(),
            t_tag: F::zero(),
        }
    }

    ///
    pub fn new_lookup(tag: F) -> Self {
        Self {
            q_m: F::zero(),
            q_l: F::zero(),
            q_r: F::zero(),
            q_o: F::zero(),
            q_c: F::zero(),
            q_lookup: F::one(),
            t_tag: tag,
        }
    }

    ///
    pub fn with_mul(mut self, q_m: F) -> Self {
        self.q_m = q_m;
        self
    }

    ///
    pub fn with_left(mut self, q_l: F) -> Self {
        self.q_l = q_l;
        self
    }

    ///
    pub fn with_right(mut self, q_r: F) -> Self {
        self.q_r = q_r;
        self
    }

    ///
    pub fn with_out(mut self, q_o: F) -> Self {
        self.q_o = q_o;
        self
    }

    ///
    pub fn with_constant(mut self, q_c: F) -> Self {
        self.q_c = q_c;
        self
    }

    ///
    pub fn with_left_lt(mut self, w_l: &LTVariable<F>) -> Self {
        let q_m = self.q_m * w_l.coeff;
        let q_l = self.q_l * w_l.coeff;
        self.q_r += self.q_m * w_l.offset;
        self.q_c += self.q_l * w_l.offset;
        self.q_m = q_m;
        self.q_l = q_l;

        self
    }

    ///
    pub fn with_right_lt(mut self, w_r: &LTVariable<F>) -> Self {
        let q_m = self.q_m * w_r.coeff;
        let q_r = self.q_r * w_r.coeff;
        self.q_l += self.q_m * w_r.offset;
        self.q_c += self.q_r * w_r.offset;
        self.q_m = q_m;
        self.q_r = q_r;

        self
    }

    ///
    pub fn with_out_lt(mut self, w_o: &LTVariable<F>) -> Self {
        let q_o = self.q_o * w_o.coeff;
        self.q_c += self.q_o * w_o.offset;
        self.q_o = q_o;

        self
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct SetupComposer<F: Field> {
    /// Number of constraints in the circuit
    pub(crate) n: usize,
    /// Product selector
    pub(crate) q_m: Vec<F>,
    /// Left wire selector
    pub(crate) q_l: Vec<F>,
    /// Right wire selector
    pub(crate) q_r: Vec<F>,
    /// Output wire selector
    pub(crate) q_o: Vec<F>,
    /// Constant wire selector
    pub(crate) q_c: Vec<F>,
    /// Lookup gate selector
    pub(crate) q_lookup: Vec<F>,
    /// Tag of lookup table
    pub(crate) t_tag: Vec<F>,

    /// Permutation argument.
    pub perm: Permutation,
    /// Positions of public inputs
    pub pp: PublicPositions,
}

impl<F: Field> SetupComposer<F> {
    ///
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            n: 0,
            q_m: Vec::new(),
            q_l: Vec::new(),
            q_r: Vec::new(),
            q_o: Vec::new(),
            q_c: Vec::new(),
            q_lookup: Vec::new(),
            t_tag: Vec::new(),
            perm: Permutation::new(),
            pp: PublicPositions::new(),
        }
    }

    ///
    pub fn with_capacity(constraint_size: usize, variable_size: usize) -> Self {
        Self {
            n: 0,
            q_m: Vec::with_capacity(constraint_size),
            q_l: Vec::with_capacity(constraint_size),
            q_r: Vec::with_capacity(constraint_size),
            q_o: Vec::with_capacity(constraint_size),
            q_c: Vec::with_capacity(constraint_size),
            q_lookup: Vec::with_capacity(constraint_size),
            t_tag: Vec::with_capacity(constraint_size),
            perm: Permutation::with_capacity(variable_size),
            pp: PublicPositions::new(),
        }
    }

    /// Adds an arithmetic gate.
    /// This gate gives total freedom to the end user to implement the
    /// corresponding circuits in the most optimized way possible because
    /// the user has access to the full set of variables, as well as
    /// selector coefficients that take part in the computation of the gate
    /// equation.
    ///
    /// The final constraint added will force the following:
    /// `(a * b) * q_m + a * q_l + b * q_r + q_c + PI + q_o * c = 0`.
    pub fn gate_constrain(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        sels: Selectors<F>,
        with_pi: bool,
    ) {
        // Add selector vectors
        self.q_l.push(sels.q_l);
        self.q_r.push(sels.q_r);
        self.q_m.push(sels.q_m);
        self.q_o.push(sels.q_o);
        self.q_c.push(sels.q_c);
        self.q_lookup.push(sels.q_lookup);
        self.t_tag.push(sels.t_tag);

        self.perm.add_variables_to_map(w_l, w_r, w_o, self.n);

        if with_pi {
            self.pp.add_input(self.n);
        }

        self.n += 1;
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub struct ProvingComposer<F: Field> {
    /// Number of arithmetic gates in the circuit
    pub(crate) n: usize,

    // Witness vectors
    /// Left wire witness vector.
    pub(crate) w_l: Vec<Variable>,
    /// Right wire witness vector.
    pub(crate) w_r: Vec<Variable>,
    /// Output wire witness vector.
    pub(crate) w_o: Vec<Variable>,

    ///
    pub var_map: VariableMap<F>,

    /// Sparse representation of the Public Inputs linking the positions of the
    /// non-zero ones to it's actual values.
    pub pi: PublicInputs<F>,
}

impl<F: Field> ProvingComposer<F> {
    /// Generates a new empty `ConstraintSystem` with all of it's fields
    /// set to hold an initial capacity of 0.
    ///
    /// # Note
    ///
    /// The usage of this may cause lots of re-allocations since the `Composer`
    /// holds `Vec` for every polynomial, and these will need to be re-allocated
    /// each time the circuit grows considerably.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            n: 0,
            w_l: Vec::new(),
            w_r: Vec::new(),
            w_o: Vec::new(),
            var_map: VariableMap::new(),
            pi: PublicInputs::new(),
        }
    }

    /// Creates a new circuit with an expected circuit size.
    /// This will allow for less reallocations when building the circuit
    /// since the `Vec`s will already have an appropriate allocation at the
    /// beginning of the composing stage.
    pub fn with_capacity(
        constraint_size: usize,
        variable_size: usize,
    ) -> Self {
        Self {
            n: 0,
            w_l: Vec::with_capacity(constraint_size),
            w_r: Vec::with_capacity(constraint_size),
            w_o: Vec::with_capacity(constraint_size),
            var_map: VariableMap::with_capacity(variable_size),
            pi: PublicInputs::new(),
        }
    }

    ///
    pub fn input_wires(
        &mut self,
        w_l: Variable,
        w_r: Variable,
        w_o: Variable,
        pi: Option<F>,
    ) {
        self.w_l.push(w_l);
        self.w_r.push(w_r);
        self.w_o.push(w_o);

        if let Some(pi) = pi {
            self.pi.add_input(self.n, pi);
        }

        self.n += 1;
    }
}

///
#[derive(derivative::Derivative)]
#[derivative(Debug)]
pub enum Composer<F: Field> {
    ///
    Setup(SetupComposer<F>),
    ///
    Proving(ProvingComposer<F>),
}

impl<F: Field> Composer<F> {
    ///
    pub fn size(&self) -> usize {
        match self {
            Composer::Setup(composer) => composer.n,
            Composer::Proving(composer) => composer.n,
        }
    }
}

impl<F: Field> Into<SetupComposer<F>> for Composer<F> {
    fn into(self) -> SetupComposer<F> {
        match self {
            Self::Setup(composer) => composer,
            _ => panic!("constraint system is not in setup mode"),
        }
    }
}

impl<F: Field> Borrow<SetupComposer<F>> for Composer<F> {
    fn borrow(&self) -> &SetupComposer<F> {
        match self {
            Self::Setup(composer) => composer,
            _ => panic!("constraint system is not in setup mode"),
        }
    }
}

impl<F: Field> BorrowMut<SetupComposer<F>> for Composer<F> {
    fn borrow_mut(&mut self) -> &mut SetupComposer<F> {
        match self {
            Self::Setup(composer) => composer,
            _ => panic!("constraint system is not in setup mode"),
        }
    }
}

impl<F: Field> Into<ProvingComposer<F>> for Composer<F> {
    fn into(self) -> ProvingComposer<F> {
        match self {
            Self::Proving(composer) => composer,
            _ => panic!("constraint system is not in proving mode"),
        }
    }
}

impl<F: Field> Borrow<ProvingComposer<F>> for Composer<F> {
    fn borrow(&self) -> &ProvingComposer<F> {
        match self {
            Self::Proving(composer) => composer,
            _ => panic!("constraint system is not in proving mode"),
        }
    }
}

impl<F: Field> BorrowMut<ProvingComposer<F>> for Composer<F> {
    fn borrow_mut(&mut self) -> &mut ProvingComposer<F> {
        match self {
            Self::Proving(composer) => composer,
            _ => panic!("constraint system is not in proving mode"),
        }
    }
}