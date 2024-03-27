// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Copyright (c) DUSK NETWORK. All rights reserved.

use ark_ff::Field;
use itertools::izip;

use super::*;

///
pub fn check_gate<F: Field, const TABLE_SIZE: usize>(
    setup: &SetupComposer<F>,
    proving: &ProvingComposer<F>,
    pub_inputs: &[F],
    table: &LookupTable<F, TABLE_SIZE>,
) {
    assert_eq!(setup.n, proving.n, "circuit size in setup not equals to proving");
    assert_eq!(setup.pp.size(), pub_inputs.len(), "arity of public inputs in setup is not correct");
    assert_eq!(proving.pi.size(), pub_inputs.len(), "arity of public inputs in proving is not correct");
    for (i, (x, y)) in proving.pi.get_vals().zip(pub_inputs.iter()).enumerate() {
        assert_eq!(x, y, "public input value at {:?} is not correct", i);
    }

    let gates = izip!(
        setup.q_m.iter(),
        setup.q_l.iter(),
        setup.q_r.iter(),
        setup.q_o.iter(),
        setup.q_c.iter(),
        setup.q_lookup.iter(),
        setup.pp.get_pos(),
        proving.w_l.iter(),
        proving.w_r.iter(),
        proving.w_o.iter(),
        proving.pi.as_evals(proving.n),
    );

    #[cfg(feature = "trace")]
    let show_trace = |i: usize| {
        let mut backtrace = setup.backtrace[i].clone();
        backtrace.resolve();
        println!("{:?}", backtrace);
    };

    for (
        i,
        (&q_m, &q_l, &q_r, &q_o, &q_c, &q_lookup, &pp, &w_l, &w_r, &w_o, pi),
    ) in gates.enumerate() {
        let a = proving.var_map.value_of_var(w_l);
        let b = proving.var_map.value_of_var(w_r);
        let c = proving.var_map.value_of_var(w_o);

        if i != pp && !pi.is_zero() {
            #[cfg(feature = "trace")]
            show_trace(i);
            panic!("public input at {:?} is not satisfied", i);
        }

        let arith_out = (q_m * a * b) + (q_l * a) + (q_r * b) + (q_o * c) + pi + q_c;
        if !arith_out.is_zero() {
            #[cfg(feature = "trace")]
            show_trace(i);
            panic!("arithmetic gate at {:?} is not satisfied", i);
        }

        let query_out = q_lookup * c;
        if !query_out.is_zero() && !table.contains(&query_out) {
            #[cfg(feature = "trace")]
            show_trace(i);
            panic!("lookup gate at {:?} is not satisfied", i);
        }
    }
}

///
pub fn test_gate_constraints<F, I, P, T, const TABLE_SIZE: usize>(
    process: P,
    pub_inputs: &[F],
    table: T,
) where
    F: Field,
    I: IntoIterator<Item = (LTVariable<F>, F)>,
    P: Fn(&mut ConstraintSystem<F, TABLE_SIZE>) -> I,
    T: Into<LookupTable<F, TABLE_SIZE>>,
{
    let table = table.into();
    let mut setup = ConstraintSystem::new(true, table.clone());
    let mut proving = ConstraintSystem::new(false, table.clone());

    process(&mut setup);
    let setup: SetupComposer<F> = setup.composer.into();

    let var_map = process(&mut proving);
    let proving: ProvingComposer<F> = proving.composer.into();
    for (lt_var, expect) in var_map {
        let actual = proving.var_map.value_of_lt_var(&lt_var);
        if actual != expect {
            #[cfg(feature = "trace")]
            {
                let backtrace = proving.var_map.backtrace_of_var(lt_var.var);
                if let Some(mut backtrace) = backtrace {
                    backtrace.resolve();
                    println!("{:?}", backtrace);
                }
            }
            panic!("value of variable {:?} is incorrect", lt_var.var);
        }
    }

    check_gate(&setup, &proving, pub_inputs, &table)
}
