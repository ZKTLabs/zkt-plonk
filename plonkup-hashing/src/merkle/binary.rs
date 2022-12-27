use std::marker::PhantomData;
use ark_ff::Field;
use itertools::Itertools;
use plonkup_core::constraint_system::*;

use crate::hasher::*;

struct Bool {
    var: Boolean,
    value: bool,
}

impl<F: Field> Uint8<F> {
    fn conditional_select(
        cs: &mut ConstraintSystem<F>,
        cond: &Bool,
        choice_a: &Self,
        choice_b: &Self,
    ) -> Self {
        let (out, out_value): (Variable, u8);
        match (choice_a, choice_b) {
            (Self::Constant(a), Self::Constant(b)) => {
                // out = (a - b) * cond + b
                out_value = if cond.value { *a } else { *b };
                out = cs.assign_variable(out_value.into());

                let sels = Selectors::new_arith()
                    .with_left(F::from(*a) - F::from(*b))
                    .with_constant(F::from(*b))
                    .with_out(-F::one());

                cs.arith_constrain(
                    cond.var.0,
                    Variable::Zero,
                    out,
                    sels,
                    None,
                );
            }
            (Self::Constant(a), Self::Variable(b)) => {
                // out = -1 * cond * b + a * cond + b
                out_value = if cond.value { *a } else { b.value };
                out = cs.assign_variable(out_value.into());

                let sels = Selectors::new_arith()
                    .with_mul(-F::one())
                    .with_left(F::from(*a))
                    .with_right(F::one())
                    .with_out(-F::one());

                cs.arith_constrain(
                    cond.var.0,
                    b.var,
                    out,
                    sels,
                    None,
                );
            }
            (Self::Variable(a), Self::Constant(b)) => {
                // out = cond * a - b * cond + b
                out_value  = if cond.value { a.value } else { *b };
                out = cs.assign_variable(out_value.into());

                let sels = Selectors::new_arith()
                    .with_mul(F::one())
                    .with_left(-F::from(*b))
                    .with_constant(F::from(*b))
                    .with_out(-F::one());

                cs.arith_constrain(
                    cond.var.0,
                    a.var,
                    out,
                    sels,
                    None,
                );
            }
            (Self::Variable(a), Self::Variable(b)) => {
                out_value  = if cond.value { a.value } else { b.value };
                out = cs.conditional_select(
                    cond.var,
                    &a.var.into(),
                    &b.var.into(),
                );
            }
        }

        Self::Variable(Uint8Var::new(out, out_value))
    }
}

fn compute_merkle_paths<F, H>(
    cs: &mut ConstraintSystem<F>,
    auth_elements: &[(Bool, BytesDigest<F>)],
    leaf_node: &BytesDigest<F>,
) -> Vec<BytesDigest<F>>
where
    F: Field,
    H: BytesHasher<F>,
{
    let mut cur_hash = leaf_node.clone();
    auth_elements
        .iter()
        .map(|(is_left, node_hash)| {
            let mut left_node = BytesDigest::with_capacity(cur_hash.len());
            let mut right_node = BytesDigest::with_capacity(cur_hash.len());
            node_hash
                .iter()
                .zip(cur_hash.iter())
                .for_each(|(node, cur)| {
                    left_node.push(Uint8::conditional_select(
                        cs,
                        is_left,
                        node,
                        cur,
                    ));
                    right_node.push(Uint8::conditional_select(
                        cs,
                        is_left,
                        cur,
                        node,
                    ));
                });
            cur_hash = H::hash_two(cs, &left_node, &right_node);

            cur_hash.clone()
        })
        .collect()
}

pub struct PoRCircuit<F, H>
where
    F: Field,
    H: BytesHasher<F>,
{
    leaf_index: u64,
    auth_nodes: Vec<[u8; 32]>,
    _f: PhantomData<F>,
    _h: PhantomData<H>,
}

impl<F, H> PoRCircuit<F, H>
where
    F: Field,
    H: BytesHasher<F>,
{
    pub fn synthesize(
        self,
        cs: &mut ConstraintSystem<F>,
        leaf_node: &BytesDigest<F>,
    ) -> (BytesDigest<F>, Vec<Boolean>) {
        let auth_elements = self.auth_nodes
            .into_iter()
            .enumerate()
            .map(|(layer, node)| {
                let value = (self.leaf_index >> layer) & 1 == 1;
                let var = cs.assign_variable(value.into());
                let var = cs.boolean_gate(var);
                let is_left = Bool { var, value };

                let node = node
                    .into_iter()
                    .map(|byte| Uint8::Variable(Uint8Var::assign(cs, byte)))
                    .collect_vec();

                (is_left, node)
            })
            .collect_vec();

        let mut paths = compute_merkle_paths::<F, H>(cs, &auth_elements, leaf_node);
        let root = paths.pop().unwrap();

        let index_bits = auth_elements
            .into_iter()
            .map(|(is_left, _)| is_left.var)
            .collect();

        (root, index_bits)
    }
}
