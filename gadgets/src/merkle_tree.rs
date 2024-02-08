use alloc::collections::BTreeMap;
use ark_ff::Field;
use array_init::array_init;
use plonk_core::error::Error;
use plonk_hashing::hasher::FieldHasher;


struct MerkleTree<
    F: Field,
    H: FieldHasher<(), F>,
    const HEIGHT: usize,
> {
    hasher: H,
    store: BTreeMap<(usize, usize), F>,
    nodes: [F; HEIGHT],
}

impl<
    F: Field,
    H: FieldHasher<(), F>,
    const HEIGHT: usize,
> MerkleTree<F, H, HEIGHT> {

    pub fn new(mut hasher: H) -> Result<Self, Error> {
        let mut nodes = [F::default(); HEIGHT];
        let mut hash = H::empty_hash();

        nodes
            .iter_mut()
            .try_for_each(|node| -> Result<(), Error> {
                *node = hash;
                hash = hasher.hash_two(&mut (), &hash, &hash)?;
                Ok(())
            })?;

        Ok(Self {
            hasher,
            store: BTreeMap::new(),
            nodes,
        })
    }

    pub fn merkle_path(&self, index: usize) -> [F; HEIGHT] {
        array_init(|layer| {
            let index = index >> layer;
            let witness = if (index & 1) == 1 {
                self.store.get(&(layer, index - 1)).unwrap_or(&self.nodes[layer])
            } else {
                self.store.get(&(layer, index + 1)).unwrap_or(&self.nodes[layer])
            };
            *witness
        })
    }

    pub fn add_leaf(&mut self, index: usize, mut hash: F) -> Result<(), Error> {
        for layer in 0..HEIGHT {
            let index = index >> layer;
            self.store.insert((layer, index), hash);

            if (index & 1) == 1 {
                let witness = self.store.get(&(layer, index - 1)).unwrap_or(&self.nodes[layer]);
                hash = self.hasher.hash_two(&mut (), witness, &hash)?;
            } else {
                let witness = self.store.get(&(layer, index + 1)).unwrap_or(&self.nodes[layer]);
                hash = self.hasher.hash_two(&mut (), &hash, witness)?;
            }
        }
        Ok(())
    }
}

