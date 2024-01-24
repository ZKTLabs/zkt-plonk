use ark_ff::Field;
use itertools::Itertools;
use plonk_core::constraint_system::{ConstraintSystem, Boolean, LTVariable};

use crate::hasher::FieldHasher;

pub fn compute_native_merkle_paths<F, H>(
    hasher: &mut H,
    witness_elements: impl IntoIterator<Item = (bool, F)>,
    leaf_node: F,
) -> Vec<F>
where
    F: Field,
    H: FieldHasher<(), F>,
{
    let mut cur_hash = leaf_node;
    witness_elements
        .into_iter()
        .map(|(is_left, node_hash)| {
            cur_hash = if is_left {
                hasher.hash_two(&mut (), &node_hash, &cur_hash)
            } else {
                hasher.hash_two(&mut (), &cur_hash, &node_hash)
            };

            cur_hash
        })
        .collect()
}

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


#[cfg(test)]
mod tests {
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use bitvec::{field::BitField, prelude::BitVec};
    use plonk_core::constraint_system::test_gate_constraints;

    use crate::hasher::poseidon::*;
    use super::*;

    const WIDTH: usize = 5;
    const HEIGHT: usize = 20;

    fn random_merkle_witness(rng: &mut StdRng) -> Vec<(bool, Fr)> {
        (0..HEIGHT).map(|_| (bool::rand(rng), Fr::rand(rng))).collect()
    }

    fn native_poseidon_hasher(param: PoseidonConstants<Fr>) -> PoseidonRef<(), NativeSpecRef<Fr>, WIDTH> {
        PoseidonRef::new(param)
    }

    fn poseidon_hasher(param: PoseidonConstants<Fr>) -> PoseidonRef<ConstraintSystem<Fr>, PlonkSpecRef, WIDTH> {
        PoseidonRef::new(param)
    }

    #[test]
    fn test_circuit() {
        test_gate_constraints(
            |cs| {
                let rng = &mut test_rng();
                let param = PoseidonConstants::generate::<WIDTH>();
                let mut hasher = native_poseidon_hasher(param.clone());

                // native merkle path computation
                let leaf = Fr::rand(rng);
                let witness_nodes: Vec<(bool, ark_ff::Fp256<ark_bn254::FrParameters>)> = random_merkle_witness(rng);
                let mut paths = compute_native_merkle_paths(
                    &mut hasher,
                    witness_nodes.clone(),
                    leaf,
                );
                let root = paths.pop().unwrap();

                // circuit merkle path computation
                let mut hasher = poseidon_hasher(param);
                let (index_iter, nodes_iter): (Vec<_>, Vec<_>)
                    = witness_nodes.into_iter().unzip();
                let circuit = PoECircuit::<Fr, HEIGHT> {
                    leaf_index: BitVec::<u8>::from_iter(index_iter).load_le(),
                    witness_nodes: nodes_iter,
                };
                let leaf_var = cs.assign_variable(leaf);
                let (root_var, _) = circuit.synthesize(
                    cs,
                    &mut hasher,
                    &leaf_var.into(),
                );

                [(root_var, root)]
            },
            &[],
        );
    }
}