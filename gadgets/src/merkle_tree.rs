use std::collections::BTreeMap;
use ark_ff::Field;
use ark_serialize::{Read, Write, CanonicalSerialize, CanonicalDeserialize, SerializationError};
use array_init::array_init;
use plonk_core::error::Error as PlonkError;
use plonk_hashing::hasher::FieldHasher;

#[derive(CanonicalSerialize, CanonicalDeserialize, Default)]
pub struct MerkleTreeStore<F: Field, const HEIGHT: usize> {
    tree: BTreeMap<(usize, usize), F>,
    root: F,
    next_index: usize,
}

impl<F: Field, const HEIGHT: usize> MerkleTreeStore<F, HEIGHT> {
    pub fn into_merkle_tree<H: FieldHasher<(), F>>(
        self,
        hasher: H,
    ) -> Result<MerkleTree<F, H, HEIGHT>, PlonkError> {
        MerkleTree::new(hasher, self)
    }
}

impl<F, H, const HEIGHT: usize> From<MerkleTree<F, H, HEIGHT>> for MerkleTreeStore<F, HEIGHT>
where
    F: Field,
    H: FieldHasher<(), F>,
{
    fn from(tree: MerkleTree<F, H, HEIGHT>) -> Self {
        tree.store
    }
}

pub struct MerkleTree<F: Field, H: FieldHasher<(), F>, const HEIGHT: usize> {
    hasher: H,
    store: MerkleTreeStore<F, HEIGHT>,
    nodes: [F; HEIGHT],
}

impl<F, H, const HEIGHT: usize> MerkleTree<F, H, HEIGHT>
where
    F: Field,
    H: FieldHasher<(), F>,
{
    pub fn new(mut hasher: H, store: MerkleTreeStore<F, HEIGHT>) -> Result<Self, PlonkError> {
        let mut nodes = [F::default(); HEIGHT];
        let mut hash = H::empty_hash();

        nodes
            .iter_mut()
            .try_for_each(|node| -> Result<(), PlonkError> {
                *node = hash;
                hash = hasher.hash_two(&mut (), &hash, &hash)?;
                Ok(())
            })?;

        Ok(Self { hasher, store, nodes })
    }

    pub fn merkle_path(&self, index: usize) -> [F; HEIGHT] {
        array_init(|layer| {
            let idx = index >> layer;
            let witness = if (idx & 1) == 1 {
                self.store.tree.get(&(layer, idx - 1)).unwrap_or(&self.nodes[layer])
            } else {
                self.store.tree.get(&(layer, idx + 1)).unwrap_or(&self.nodes[layer])
            };
            *witness
        })
    }

    pub fn add_leaf(&mut self, mut hash: F) -> Result<usize, PlonkError> {
        let index = self.store.next_index;
        self.store.next_index += 1;
        for layer in 0..HEIGHT {
            let idx = index >> layer;
            self.store.tree.insert((layer, idx), hash);

            if (idx & 1) == 1 {
                let witness = self.store.tree.get(&(layer, idx - 1)).unwrap_or(&self.nodes[layer]);
                hash = self.hasher.hash_two(&mut (), witness, &hash)?;
            } else {
                let witness = self.store.tree.get(&(layer, idx + 1)).unwrap_or(&self.nodes[layer]);
                hash = self.hasher.hash_two(&mut (), &hash, witness)?;
            }
        }
        self.store.root = hash;
        Ok(index)
    }
    
    pub fn root(&self) -> F {
        self.store.root
    }
}
