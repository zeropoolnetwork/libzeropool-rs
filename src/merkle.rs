use std::collections::HashSet;

use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database as WebDatabase;

use libzeropool::constants;
use libzeropool::fawkes_crypto::core::sizedvec::SizedVec;
use libzeropool::fawkes_crypto::ff_uint::{Num, PrimeField};
use libzeropool::fawkes_crypto::native::poseidon::{poseidon, MerkleProof};
use libzeropool::native::params::PoolParams;

type Hash<F> = Num<F>;

pub struct MerkleTree<'p, D: KeyValueDB, P: PoolParams> {
    db: D,
    params: &'p P,
    default_hashes: Vec<Hash<P::Fr>>,
}

impl<'p, P: PoolParams> MerkleTree<'p, WebDatabase, P> {
    pub async fn new_web(name: &str, params: &'p P) -> MerkleTree<'p, WebDatabase, P> {
        let db = WebDatabase::open(name.to_owned(), 1).await.unwrap();

        MerkleTree {
            db,
            default_hashes: Self::gen_default_hashes(params),
            params,
        }
    }
}

impl<'p, D: KeyValueDB, P: PoolParams> MerkleTree<'p, D, P> {
    pub fn new(db: D, params: &'p P) -> MerkleTree<'p, D, P> {
        MerkleTree {
            db,
            default_hashes: Self::gen_default_hashes(params),
            params,
        }
    }

    /// Add hash for an element with a certain index
    /// Set `temporary` to true if you want this leaf and all unneeded connected nodes to be removed
    /// during cleanup.
    pub fn add_hash(&mut self, index: u32, hash: Hash<P::Fr>, temporary: bool) {
        let mut batch = self.db.transaction();

        let hash_serialized = hash.try_to_vec().unwrap();

        let key = Self::node_key(0, index);
        batch.put(0, &key, &hash_serialized);

        if !temporary {
            // mark this hash as non-removable for later
            let key = Self::retained_node_key(index);
            batch.put(1, &key, &hash_serialized);
        }

        // update inner nodes
        self.update_path_batched(&mut batch, 0, index, hash);

        self.db.write(batch).unwrap();
    }

    /// Add multiple hashes from an array of tuples (index, hash, temporary)
    pub fn add_hashes<'a, I>(&mut self, hashes: I)
    where
        I: IntoIterator<Item = &'a (u32, Hash<P::Fr>, bool)>,
        I::IntoIter: 'a,
        P::Fr: 'a,
    {
        for (index, hash, temporary) in hashes.into_iter().cloned() {
            self.add_hash(index, hash, temporary);
        }

        // self.cleanup();
    }

    pub fn add_subtree(&mut self, hashes: &[Hash<P::Fr>], start_index: u32, temporary: bool) {
        let size = hashes.len();

        assert!(
            (size & (size - 1)) == 0,
            "subtree size should be a power of 2"
        );
        assert!(
            start_index % hashes.len() as u32 == 0,
            "subtree should be on correct position in the tree"
        );

        let mut batch = self.db.transaction();

        // set leaves
        for index_shift in 0..size {
            let index = start_index + index_shift as u32;

            self.set_batched(&mut batch, 0, index, hashes[index_shift]);

            if !temporary {
                // mark this hash as non-removable for later
                self.set_retained_batched(&mut batch, index, hashes[index_shift]);
            }
        }

        // build subtree
        let mut child_hashes = hashes.to_vec();
        let mut height: u32 = 0;
        let mut current_start_index = start_index;
        while child_hashes.len() > 1 {
            height += 1;
            current_start_index /= 2;

            let parents_size = child_hashes.len() / 2;
            let mut parent_hashes = Vec::with_capacity(parents_size);

            for parent_index_shift in 0..parents_size {
                let hash_left = child_hashes[2 * parent_index_shift];
                let hash_right = child_hashes[2 * parent_index_shift + 1];
                let hash_parent =
                    poseidon([hash_left, hash_right].as_ref(), self.params.compress());

                let parent_index = current_start_index + parent_index_shift as u32;
                self.set_batched(&mut batch, height, parent_index, hash_parent);
                parent_hashes.push(hash_parent);
            }

            child_hashes = parent_hashes;
        }

        // update path to the root
        self.update_path_batched(&mut batch, height, current_start_index, child_hashes[0]);

        self.db.write(batch).unwrap();

        // self.cleanup();
    }

    pub fn get(&self, height: u32, index: u32) -> Hash<P::Fr> {
        match self.get_opt(height, index) {
            Some(val) => val,
            _ => self.default_hashes[height as usize],
        }
    }

    pub fn get_opt(&self, height: u32, index: u32) -> Option<Hash<P::Fr>> {
        assert!(height <= constants::HEIGHT as u32);

        let key = Self::node_key(height, index);
        let res = self.db.get(0, &key);

        match res {
            Ok(Some(ref val)) => Some(Hash::<P::Fr>::try_from_slice(val).unwrap()),
            _ => None,
        }
    }

    pub fn set(&self, height: u32, index: u32, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();
        self.set_batched(&mut batch, height, index, hash);
        self.db.write(batch).unwrap();
    }

    /// Remove a non-temporary hash
    pub fn remove_hash(&mut self, index: u32) {
        let hash = self.get(0, index);

        if hash == self.default_hashes[0] {
            return;
        }

        let mut batch = self.db.transaction();

        let key = Self::retained_node_key(index);
        batch.delete(1, &key);

        let _ = self.db.write(batch);
    }

    pub fn get_proof(&self, index: u32) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>> {
        // TODO: Add Default for SizedVec or make it's member public to replace all those iterators.
        let key = Self::retained_node_key(index);
        let leaf_present = self.db.get(1, &key).map_or(false, |value| value.is_some());

        if !leaf_present {
            return None;
        }

        let mut sibling: SizedVec<_, { constants::HEIGHT }> =
            (0..constants::HEIGHT).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { constants::HEIGHT }> =
            (0..constants::HEIGHT).map(|_| false).collect();

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_left))| {
                let h = h as u32;
                *is_left = x % 2 == 0;
                *sibling = self.get(h, x ^ 1);

                x / 2
            },
        );

        Some(MerkleProof { sibling, path })
    }

    pub fn get_all_nodes(&self) -> Vec<Node<P::Fr>> {
        self.db
            .iter(0)
            .map(|(key, value)| {
                let mut key_buf = &key[..];
                let y = key_buf.read_u32::<BigEndian>().unwrap(); // height
                let x = key_buf.read_u32::<BigEndian>().unwrap(); // index
                let value = Hash::try_from_slice(&value).unwrap();

                Node {
                    index: x,
                    height: y,
                    value,
                }
            })
            .collect()
    }

    pub fn cleanup(&mut self) {
        let mut used_hashes = HashSet::new(); // TODO: Preallocate?
        let permanent_hashes = self.db.iter(1);

        // Collect all used nodes
        for (key, value) in permanent_hashes {
            let value = Hash::<P::Fr>::try_from_slice(&value).unwrap();
            used_hashes.insert(value.to_uint());

            let mut key_buf = &key[..];
            let index = key_buf.read_u32::<BigEndian>().unwrap();
            let proof = self.get_proof(index).unwrap(); // always present

            for hash in proof.sibling.iter() {
                used_hashes.insert(hash.to_uint());
            }
        } // FIXME: add the proof of the last hash

        // Remove unused
        let mut to_remove = Vec::new();
        for (key, value) in self.db.iter(0) {
            let value = Hash::<P::Fr>::try_from_slice(&value).unwrap();

            if !used_hashes.contains(&value.to_uint()) {
                let mut key_buf = &key[..];
                let height = key_buf.read_u32::<BigEndian>().unwrap();
                let index = key_buf.read_u32::<BigEndian>().unwrap();

                to_remove.push((height, index));
            }
        }

        let mut batch = self.db.transaction();

        for (height, index) in to_remove {
            self.remove_batched(&mut batch, height, index);
        }

        self.db.write(batch).unwrap();
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: u32, index: u32) {
        let key = Self::node_key(height, index);
        batch.delete(0, &key);
    }

    fn set_batched(&self, batch: &mut DBTransaction, height: u32, index: u32, hash: Hash<P::Fr>) {
        let key = Self::node_key(height, index);
        let hash = hash.try_to_vec().unwrap();
        batch.put(0, &key, &hash);
    }

    fn set_retained_batched(&self, batch: &mut DBTransaction, index: u32, hash: Hash<P::Fr>) {
        let key = Self::retained_node_key(index);
        let hash = hash.try_to_vec().unwrap();
        batch.put(1, &key, &hash);
    }

    fn update_path_batched(
        &mut self,
        batch: &mut DBTransaction,
        height: u32,
        index: u32,
        hash: Hash<P::Fr>,
    ) {
        let mut child_index = index;
        let mut child_hash = hash;
        // todo: improve
        for current_height in height + 1..constants::HEIGHT as u32 {
            let parent_index = child_index / 2;

            // get pair of children
            let second_child_index = child_index ^ 1;
            let pair = if child_index % 2 == 0 {
                [child_hash, self.get(current_height - 1, second_child_index)]
            } else {
                [self.get(current_height - 1, second_child_index), child_hash]
            };
            let hash = poseidon(pair.as_ref(), self.params.compress());
            self.set_batched(batch, current_height, parent_index, hash);

            child_index = parent_index;
            child_hash = hash;
        }
    }

    #[inline]
    fn node_key(height: u32, index: u32) -> [u8; 8] {
        let mut data = [0u8; 8];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u32::<BigEndian>(height);
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        data
    }

    #[inline]
    fn retained_node_key(index: u32) -> [u8; 4] {
        let mut data = [0; 4];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        data
    }

    fn gen_default_hashes(params: &P) -> Vec<Hash<P::Fr>> {
        let zero = poseidon(&[Num::ZERO], params.compress());
        let mut default_hashes = vec![zero; constants::HEIGHT];

        for i in 1..constants::HEIGHT {
            let t = default_hashes[i - 1];
            default_hashes[i] = poseidon([t, t].as_ref(), params.compress());
        }

        default_hashes
    }

    #[inline]
    fn index_at(height: u32, index: u32) -> u32 {
        (index as usize / 2usize.pow(height)) as u32
    }
}

#[derive(Debug)]
pub struct Node<F: PrimeField> {
    pub index: u32,
    pub height: u32,
    pub value: Num<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::CustomRng;
    use kvdb_memorydb::create;
    use libzeropool::fawkes_crypto::ff_uint::rand::Rng;
    use libzeropool::POOL_PARAMS;
    use test_case::test_case;

    #[test]
    fn test_add_hashes_first_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), &*POOL_PARAMS);

        let hashes: Vec<_> = (0..3).map(|n| (n, rng.gen(), false)).collect();
        tree.add_hashes(&hashes);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 3);

        for h in 0..constants::HEIGHT as u32 {
            assert!(tree.get_opt(h, 0).is_some()); // TODO: Compare with expected hash
        }

        for (i, tuple) in hashes.iter().enumerate() {
            assert_eq!(tree.get(0, tuple.0), hashes[i].1);
        }
    }

    #[test]
    fn test_add_hashes_last_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), &*POOL_PARAMS);

        let hashes: Vec<_> = (u32::MAX - 2..=u32::MAX)
            .map(|n| (n, rng.gen(), false))
            .collect();
        tree.add_hashes(&hashes);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 3);

        for h in 0..constants::HEIGHT as u32 {
            let index = u32::MAX / 2u32.pow(h);
            assert!(tree.get_opt(h, index).is_some()); // TODO: Compare with expected hash
        }

        for (i, tuple) in hashes.iter().enumerate() {
            assert_eq!(tree.get(0, tuple.0), hashes[i].1);
        }
    }

    #[test]
    fn test_add_hashes_cleanup() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), &*POOL_PARAMS);

        let mut hashes: Vec<_> = (0..6).map(|n| (n, rng.gen(), false)).collect();

        // make some hashes temporary
        // these two must remain after cleanup
        hashes[1].2 = true;
        hashes[3].2 = true;

        // these two must be removed
        hashes[4].2 = true;
        hashes[5].2 = true;

        tree.add_hashes(&hashes);
        tree.cleanup();

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), 7);
        assert_eq!(tree.get_opt(0, 4), None);
        assert_eq!(tree.get_opt(0, 5), None);
    }

    #[test]
    fn test_get_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), &*POOL_PARAMS);
        let proof = tree.get_proof(123);

        assert!(proof.is_none());

        tree.add_hash(123, rng.gen(), false);
        let proof = tree.get_proof(123).unwrap();

        assert_eq!(proof.sibling.as_slice().len(), constants::HEIGHT);
        assert_eq!(proof.path.as_slice().len(), constants::HEIGHT);
    }

    #[test_case(1, 0)]
    #[test_case(2, 0)]
    #[test_case(16, 0)]
    #[test_case(1, 7)]
    #[test_case(2, 6)]
    #[test_case(16, 32)]
    #[test_case(1, constants::HEIGHT - 1)]
    #[test_case(2, constants::HEIGHT - 2)]
    #[test_case(16, constants::HEIGHT - 16)]
    fn test_add_subtree(subtree_size: usize, start_index: usize) {
        let mut rng = CustomRng;
        let mut tree_add_hashes = MerkleTree::new(create(2), &*POOL_PARAMS);
        let mut tree_add_subtree = MerkleTree::new(create(2), &*POOL_PARAMS);

        let hash_values: Vec<_> = (0..subtree_size).map(|_| rng.gen()).collect();
        let hashes: Vec<_> = (0..subtree_size)
            .map(|n| ((start_index + n) as u32, hash_values[n], false))
            .collect();

        tree_add_hashes.add_hashes(&hashes);
        tree_add_subtree.add_subtree(&hash_values, start_index as u32, false);

        let nodes_add_hashes = tree_add_hashes.get_all_nodes();
        let nodes_add_subtree = tree_add_subtree.get_all_nodes();
        assert_eq!(nodes_add_hashes.len(), nodes_add_subtree.len());

        for first_node in &nodes_add_hashes {
            let mut found = false;
            for second_note in &nodes_add_subtree {
                if first_node.height == second_note.height
                    && first_node.index == second_note.index
                    && first_node.value == second_note.value
                {
                    found = true;
                    break;
                }
            }
            assert!(
                found,
                "node not found height: {}, index: {}",
                first_node.height, first_node.index
            );
        }
    }
}
