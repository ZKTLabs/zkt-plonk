// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::Field;
use itertools::izip;

use super::{ConstraintSystem, SetupComposer, ProvingComposer};

///
pub fn check_arith_gate<F: Field>(
    setup: &SetupComposer<F>,
    proving: &ProvingComposer<F>,
    pub_inputs: &[F],
) {
    assert_eq!(setup.n, proving.n, "circuit size in setup not equals to proving");

    assert_eq!(setup.pp.size(), pub_inputs.len(), "public inputs count in setup is not correct");

    assert_eq!(proving.pi.size(), pub_inputs.len(), "public inputs count in proving is not correct");

    for (i, (x, y)) in proving.pi.get_vals().zip(pub_inputs.iter()).enumerate() {
        assert_eq!(x, y, "public input value at {:?} is not correct", i);
    }

    let gates = izip!(
        setup.q_m.iter(),
        setup.q_l.iter(),
        setup.q_r.iter(),
        setup.q_o.iter(),
        setup.q_c.iter(),
        proving.w_l.iter(),
        proving.w_r.iter(),
        proving.w_o.iter(),
        proving.pi.as_evals(proving.n),
    );

    for (i, (&q_m, &q_l, &q_r, &q_o, &q_c, &w_l, &w_r, &w_o, pi)) in gates.enumerate() {
        let a = proving.var_map.value_of_var(w_l);
        let b = proving.var_map.value_of_var(w_r);
        let c = proving.var_map.value_of_var(w_o);
        let out = (q_m * a * b) + (q_l * a) + (q_r * b) + (q_o * c) + pi + q_c;

        assert!(out.is_zero(), "arithmetic gate at {:?} is not satisfied", i);
    }
}

///
pub fn test_arith_gate<F, Fn>(mut synthesize: Fn, pub_inputs: &[F])
where
    F: Field,
    Fn: FnMut(&mut ConstraintSystem<F>),
{
    let mut setup = ConstraintSystem::new(true);
    let mut proving = ConstraintSystem::new(false);

    synthesize(&mut setup);
    synthesize(&mut proving);

    check_arith_gate(
        setup.composer.setup_ref(),
        proving.composer.proving_ref(),
        pub_inputs,
    )
}