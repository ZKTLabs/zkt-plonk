use ark_ff::Field;
use itertools::Itertools;
use plonk_core::constraint_system::{ConstraintSystem, Boolean, LTVariable};

use crate::hasher::FieldHasher;

fn compute_merkle_paths<F, H>(
    hasher: &mut H,
    cs: &mut ConstraintSystem<F>,
    witness_elements: impl IntoIterator<Item = (Boolean, LTVariable<F>)>,
    leaf_node: &LTVariable<F>,
) -> Vec<LTVariable<F>>
where
    F: Field,
    H: FieldHasher<ConstraintSystem<F>, LTVariable<F>>,
{
    let mut cur_hash = *leaf_node;
    witness_elements
        .into_iter()
        .map(|(is_left, node_hash)| {
            let left_node = cs.conditional_select(is_left, &node_hash, &cur_hash);
            let right_node = cs.conditional_select(is_left, &cur_hash, &node_hash);
            cur_hash = hasher.hash_two(cs, &left_node.into(), &right_node.into());
            hasher.reset();

            cur_hash
        })
        .collect()
}

/// Proof of Existance Circuit
pub struct PoECircuit<F: Field, const HEIGHT: usize> {
    leaf_index: u64,
    witness_nodes: Vec<F>,
}

impl<F: Field, const HEIGHT: usize> PoECircuit<F, HEIGHT> {
    pub fn synthesize<H: FieldHasher<ConstraintSystem<F>, LTVariable<F>>>(
        self,
        cs: &mut ConstraintSystem<F>,
        hasher: &mut H,
        leaf_node: &LTVariable<F>,
    ) -> (LTVariable<F>, Vec<Boolean>) {
        assert_eq!(self.witness_nodes.len(), HEIGHT, "invalid auth path length");

        let positions = (0..HEIGHT)
            .map(|layer| {
                let value = (self.leaf_index >> layer) & 1 == 1;
                let var = cs.assign_variable(value.into());
                cs.boolean_gate(var)
            })
            .collect_vec();
        let witness_elements = positions
            .clone()
            .into_iter()
            .zip(
                self.witness_nodes
                    .into_iter()
                    .map(|node| cs.assign_variable(node).into())
            )
            .collect_vec();

        let mut paths = compute_merkle_paths(
            hasher,
            cs,
            witness_elements,
            leaf_node,
        );
        let root = paths.pop().unwrap();

        (root, positions)
    }
}
