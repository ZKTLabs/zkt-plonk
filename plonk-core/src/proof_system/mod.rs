// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

//! PLONK Proving System

mod linearisation_poly;
mod quotient_poly;
mod keys;
mod prove;
mod setup;
mod proof;

pub(crate) use prove::prove;
pub(crate) use setup::setup;

pub use proof::*;
pub use keys::*;
