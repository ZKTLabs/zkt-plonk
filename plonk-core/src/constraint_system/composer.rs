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

use ark_ff::Field;

use crate::{
    permutation::Permutation,
    proof_system::{PublicInputs, PublicPositions},
};

use super::{Variable, VariableMap};

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

    /// Permutation argument.
    pub perm: Permutation,
    /// Positions of public inputs
    pub pp: PublicPositions,
}

impl<F: Field> SetupComposer<F> {
    ///
    pub fn new() -> Self {
        Self {
            n: 0,
            q_m: Vec::new(),
            q_l: Vec::new(),
            q_r: Vec::new(),
            q_o: Vec::new(),
            q_c: Vec::new(),
            q_lookup: Vec::new(),
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
            perm: Permutation::with_capacity(variable_size),
            pp: PublicPositions::new(),
        }
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
    pub fn unwrap_setup(self) -> SetupComposer<F> {
        match self {
            Self::Setup(composer) => composer,
            _ => panic!("constraint system is not in setup mode"),
        }
    }

    ///
    pub fn setup_ref(&self) -> &SetupComposer<F> {
        match self {
            Self::Setup(composer) => composer,
            _ => panic!("constraint system is not in setup mode"),
        }
    }

    ///
    pub fn unwrap_proving(self) -> ProvingComposer<F> {
        match self {
            Self::Proving(composer) => composer,
            _ => panic!("constraint system is not in proving mode"),
        }
    }

    ///
    pub fn proving_ref(&self) -> &ProvingComposer<F> {
        match self {
            Self::Proving(composer) => composer,
            _ => panic!("constraint system is not in proving mode"),
        }
    }
}
