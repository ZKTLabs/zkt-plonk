use ark_ff::Field;
use itertools::Itertools;
use derivative::Derivative;
use plonk_core::{constraint_system::{ConstraintSystem, Boolean, LTVariable}, error::Error};

use crate::hasher::{FieldHasher, FieldHasherGenerator};

fn merkle_proof<F, G, H, const TABLE_SIZE: usize>(
    hasher: &mut H,
    cs: &mut ConstraintSystem<F, TABLE_SIZE>,
    path_elements: impl IntoIterator<Item = (Boolean, LTVariable<F>)>,
    leaf_node: &LTVariable<F>,
) -> Result<Vec<LTVariable<F>>, Error>
where
    F: Field,
    G: FieldHasherGenerator<H::Params>,
    H: FieldHasher<ConstraintSystem<F, TABLE_SIZE>, LTVariable<F>, G>,
{
    let mut cur_hash = *leaf_node;
    path_elements
        .into_iter()
        .map(|(is_left, node_hash)| {
            let left_node = cs.conditional_select(is_left, &node_hash, &cur_hash);
            let right_node = cs.conditional_select(is_left, &cur_hash, &node_hash);
            cur_hash = hasher.hash_two(cs, &left_node.into(), &right_node.into())?;

            Ok(cur_hash)
        })
        .collect()
}

/// Proof of Existance Circuit
#[derive(Derivative, Clone, Copy)]
#[derivative(Debug(bound = ""), Default(bound = ""))]
pub struct PoECircuit<F: Field, const HEIGHT: usize> {
    pub leaf_index: usize,
    #[derivative(Default(value = "[F::default(); HEIGHT]"))]
    pub path_elements: [F; HEIGHT],
}

impl<F: Field, const HEIGHT: usize> PoECircuit<F, HEIGHT> {
    pub fn synthesize<H, G, const TABLE_SIZE: usize>(
        self,
        cs: &mut ConstraintSystem<F, TABLE_SIZE>,
        hasher: &mut H,
        leaf_node: &LTVariable<F>,
    ) -> Result<(LTVariable<F>, Vec<Boolean>), Error>
    where
        H: FieldHasher<ConstraintSystem<F, TABLE_SIZE>, LTVariable<F>, G>,
        G: FieldHasherGenerator<H::Params>,
    {
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
                self.path_elements
                    .into_iter()
                    .map(|node| cs.assign_variable(node).into())
            )
            .collect_vec();

        let mut paths = merkle_proof(
            hasher,
            cs,
            witness_elements,
            leaf_node,
        )?;
        let root = paths.pop().unwrap();

        Ok((root, positions))
    }
}


#[cfg(test)]
mod tests {
    use alloc::rc::Rc;
    use ark_bn254::Fr;
    use ark_std::{test_rng, UniformRand, rand::prelude::StdRng};
    use bitvec::{field::BitField, prelude::BitVec};
    use array_init::{array_init, map_array_init};
    use plonk_core::{constraint_system::test_gate_constraints, lookup::LookupTable};

    use crate::hasher::*;
    use super::*;

    const WIDTH: usize = 5;
    const HEIGHT: usize = 20;

    #[derive(Debug)]
    struct PoseidonGenerator;

    impl FieldHasherGenerator<Rc<PoseidonConstants<Fr, WIDTH>>> for PoseidonGenerator
    {
        fn generate() -> Rc<PoseidonConstants<Fr, WIDTH>> {
            Rc::new(PoseidonConstants::generate())
        }
    }

    fn random_merkle_witness(rng: &mut StdRng) -> [(bool, Fr); HEIGHT] {
        array_init(|_| (bool::rand(rng), Fr::rand(rng)))
    }

    fn native_poseidon_hasher(param: Rc<PoseidonConstants<Fr, WIDTH>>)
        -> PoseidonRef<(), NativePlonkSpecRef<Fr>, PoseidonGenerator, WIDTH>
    {
        PoseidonRef::new(&param)
    }

    fn poseidon_hasher(param: Rc<PoseidonConstants<Fr, WIDTH>>)
        -> PoseidonRef<ConstraintSystem<Fr, 0>, PlonkSpecRef, PoseidonGenerator, WIDTH>
    {
        PoseidonRef::new(&param)
    }

    fn native_merkle_proof(
        hasher: &mut PoseidonRef<(), NativePlonkSpecRef<Fr>, PoseidonGenerator, WIDTH>,
        path_elements: impl IntoIterator<Item = (bool, Fr)>,
        leaf_node: Fr,
    ) -> Result<Vec<Fr>, Error> {
        let mut cur_hash = leaf_node;
        path_elements
            .into_iter()
            .map(|(is_left, node_hash)| {
                cur_hash = if is_left {
                    hasher.hash_two(&mut (), &node_hash, &cur_hash)?
                } else {
                    hasher.hash_two(&mut (), &cur_hash, &node_hash)?
                };

                Ok(cur_hash)
            })
            .collect()
    }

    #[test]
    fn test_circuit() {
        test_gate_constraints(
            |cs| {
                let rng = &mut test_rng();
                let param = PoseidonGenerator::generate();
                let mut hasher = native_poseidon_hasher(param.clone());

                // native merkle path computation
                let leaf = Fr::rand(rng);
                let witness_nodes= random_merkle_witness(rng);
                let mut paths = native_merkle_proof(
                    &mut hasher,
                    witness_nodes,
                    leaf,
                ).expect("native merkle proof failed");
                let root = paths.pop().unwrap();

                // circuit merkle path computation
                let mut hasher = poseidon_hasher(param);
                let index_array = map_array_init(&witness_nodes, |(index, _)| *index);
                let nodes_array = map_array_init(&witness_nodes, |(_, node)| *node);
                let circuit = PoECircuit::<Fr, HEIGHT> {
                    leaf_index: BitVec::<u8>::from_iter(index_array).load_le(),
                    path_elements: nodes_array,
                };
                let leaf_var = cs.assign_variable(leaf);
                let (root_var, _) = circuit.synthesize(
                    cs,
                    &mut hasher,
                    &leaf_var.into(),
                ).expect("circuit merkle proof failed");

                [(root_var, root)]
            },
            &[],
            LookupTable::default(),
        );
    }
}