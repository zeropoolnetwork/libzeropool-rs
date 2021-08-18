use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kvdb::{DBTransaction, KeyValueDB};
#[cfg(feature = "native")]
use kvdb_rocksdb::{Database as NativeDatabase, DatabaseConfig};
#[cfg(feature = "web")]
use kvdb_web::Database as WebDatabase;
use libzeropool::{
    constants,
    fawkes_crypto::core::sizedvec::SizedVec,
    fawkes_crypto::ff_uint::{Num, PrimeField},
    fawkes_crypto::native::poseidon::{poseidon, MerkleProof},
    native::params::PoolParams,
};

pub type Hash<F> = Num<F>;

pub struct MerkleTree<D: KeyValueDB, P: PoolParams> {
    db: D,
    params: P,
    default_hashes: Vec<Hash<P::Fr>>,
    last_index: u64,
}

#[cfg(feature = "native")]
pub type NativeMerkleTree<P> = MerkleTree<NativeDatabase, P>;

#[cfg(feature = "web")]
pub type WebMerkleTree<P> = MerkleTree<WebDatabase, P>;

#[cfg(feature = "web")]
impl<P: PoolParams> MerkleTree<WebDatabase, P> {
    pub async fn new_web(name: &str, params: P) -> MerkleTree<WebDatabase, P> {
        let db = WebDatabase::open(name.to_owned(), 1).await.unwrap();

        Self::new(db, params)
    }
}

#[cfg(feature = "native")]
impl<P: PoolParams> MerkleTree<NativeDatabase, P> {
    pub fn new_native(
        config: &DatabaseConfig,
        path: &str,
        params: P,
    ) -> std::io::Result<MerkleTree<NativeDatabase, P>> {
        let db = NativeDatabase::open(config, path)?;

        Ok(Self::new(db, params))
    }
}

// TODO: Proper error handling.
impl<D: KeyValueDB, P: PoolParams> MerkleTree<D, P> {
    pub fn new(db: D, params: P) -> Self {
        // TODO: Optimize, this is extremely inefficient. Cache the number of leaves or ditch kvdb?
        let mut last_index = 0;
        for (k, _v) in db.iter(0) {
            let (height, index) = Self::parse_node_key(&k);

            if height == 0 && index > last_index {
                last_index = index;
            }
        }

        MerkleTree {
            db,
            default_hashes: Self::gen_default_hashes(&params),
            params,
            last_index,
        }
    }

    /// Add hash for an element with a certain index
    /// Set `temporary` to true if you want this leaf and all unneeded connected nodes to be removed
    /// during cleanup.
    pub fn add_hash(&mut self, index: u64, hash: Hash<P::Fr>, temporary: bool) {
        let mut batch = self.db.transaction();

        // add leaf
        let temporary_leaves_count = if temporary { 1 } else { 0 };
        self.set_batched(&mut batch, 0, index, hash, temporary_leaves_count);

        // update inner nodes
        self.update_path_batched(&mut batch, 0, index, hash, temporary_leaves_count);

        self.db.write(batch).unwrap();

        if index > self.last_index {
            self.last_index = index;
        }
    }

    pub fn append_hash(&mut self, hash: Hash<P::Fr>, temporary: bool) -> u64 {
        let index = self.last_index + 1;
        self.add_hash(index, hash, temporary);
        index
    }

    /// Add multiple hashes from an array of tuples (index, hash, temporary)
    pub fn add_hashes<I>(&mut self, hashes: I)
    where
        I: IntoIterator<Item = (u64, Hash<P::Fr>, bool)>,
    {
        for (index, hash, temporary) in hashes.into_iter() {
            self.add_hash(index, hash, temporary);
        }
    }

    pub fn add_subtree(&mut self, hashes: &[Hash<P::Fr>], start_index: u64) {
        let size = hashes.len();

        assert_eq!(
            (size & (size - 1)),
            0,
            "subtree size should be a power of 2"
        );
        assert_eq!(
            start_index % hashes.len() as u64,
            0,
            "subtree should be on correct position in the tree"
        );

        let mut batch = self.db.transaction();

        // set leaves
        for index_shift in 0..size {
            // all leaves in subtree are permanent
            self.set_batched(
                &mut batch,
                0,
                start_index + index_shift as u64,
                hashes[index_shift],
                0,
            );
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

                let parent_index = current_start_index + parent_index_shift as u64;
                self.set_batched(&mut batch, height, parent_index, hash_parent, 0);
                parent_hashes.push(hash_parent);
            }

            child_hashes = parent_hashes;
        }

        // update path to the root
        self.update_path_batched(&mut batch, height, current_start_index, child_hashes[0], 0);

        self.db.write(batch).unwrap();
    }

    pub fn add_subtree_root(&mut self, height: u32, index: u64, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();

        // add root
        self.set_batched(&mut batch, height, index, hash, 1 << height);

        // update path
        self.update_path_batched(&mut batch, height, index, hash, 1 << height);

        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: u32, index: u64) -> Hash<P::Fr> {
        match self.get_opt(height, index) {
            Some(val) => val,
            _ => self.default_hashes[height as usize],
        }
    }

    pub fn get_root(&self) -> Hash<P::Fr> {
        self.get(constants::HEIGHT as u32 - 1, 0)
    }

    pub fn get_opt(&self, height: u32, index: u64) -> Option<Hash<P::Fr>> {
        assert!(height <= constants::HEIGHT as u32);

        let key = Self::node_key(height, index);
        let res = self.db.get(0, &key);

        match res {
            Ok(Some(ref val)) => Some(Hash::<P::Fr>::try_from_slice(val).unwrap()),
            _ => None,
        }
    }

    pub fn get_proof(&self, index: u64) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>> {
        // TODO: Add Default for SizedVec or make it's member public to replace all those iterators.
        let key = Self::node_key(0, index);
        let leaf_present = self.db.get(0, &key).map_or(false, |value| value.is_some());

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

    /// Returns proof
    pub fn get_proof_for_new<I>(
        &mut self,
        new_hashes: I,
    ) -> Vec<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        // TODO: Optimize, no need to mutate the database.
        let index_offset = self.last_index + 1;
        self.add_hashes(new_hashes.into_iter().enumerate().map(|(index, hash)| {
            let new_index = index_offset + index as u64;
            (new_index, hash, true)
        }));

        let proofs = (index_offset..=self.last_index)
            .map(|index| {
                self.get_proof(index)
                    .expect("Leaf was expected to be present (bug)")
            })
            .collect();

        // FIXME: Not all nodes are deleted here
        let mut batch = self.db.transaction();
        for index in index_offset..=self.last_index {
            self.remove_batched(&mut batch, 0, index);
        }
        self.db.write(batch).unwrap();

        proofs
    }

    pub fn clean(&mut self) {
        self.clean_before_index(u64::MAX);
    }

    pub fn clean_before_index(&mut self, clean_before_index: u64) {
        let mut batch = self.db.transaction();

        // get all nodes
        // todo: improve performance?
        let mut keys: Vec<(u32, u64)> = self
            .db
            .iter(0)
            .map(|(key, _value)| Self::parse_node_key(&key))
            .collect();
        // remove unnecessary nodes
        for (height, index) in keys {
            // leaves have no children
            if height == 0 {
                continue;
            }

            // remove only nodes before specified index
            if index * (1 << height) >= clean_before_index {
                continue;
            }

            let parent_temporary_leaves_count = self.get_temporary_count(height, index);
            if parent_temporary_leaves_count == (1 << height) {
                // all leaves in subtree are temporary, we can keep only subtree root
                self.remove_batched(&mut batch, height - 1, 2 * index);
                self.remove_batched(&mut batch, height - 1, 2 * index + 1);
            }
        }

        self.db.write(batch).unwrap();
    }

    pub fn get_all_nodes(&self) -> Vec<Node<P::Fr>> {
        self.db
            .iter(0)
            .map(|(key, value)| {
                let mut key_buf = &key[..];
                let height = key_buf.read_u32::<BigEndian>().unwrap();
                let index = key_buf.read_u64::<BigEndian>().unwrap();
                let value = Hash::try_from_slice(&value).unwrap();

                Node {
                    index,
                    height,
                    value,
                }
            })
            .collect()
    }

    fn update_path_batched(
        &mut self,
        batch: &mut DBTransaction,
        height: u32,
        index: u64,
        hash: Hash<P::Fr>,
        temporary_leaves_count: u64,
    ) {
        let mut child_index = index;
        let mut child_hash = hash;
        let mut child_temporary_leaves_count = temporary_leaves_count;
        // todo: improve
        for current_height in height + 1..constants::HEIGHT as u32 {
            let parent_index = child_index / 2;

            // get pair of children
            let second_child_index = child_index ^ 1;

            // compute hash
            let pair = if child_index % 2 == 0 {
                [child_hash, self.get(current_height - 1, second_child_index)]
            } else {
                [self.get(current_height - 1, second_child_index), child_hash]
            };
            let hash = poseidon(pair.as_ref(), self.params.compress());

            // compute temporary leaves count
            let second_child_temporary_leaves_count =
                self.get_temporary_count(current_height - 1, second_child_index);
            let parent_temporary_leaves_count =
                child_temporary_leaves_count + second_child_temporary_leaves_count;

            self.set_batched(
                batch,
                current_height,
                parent_index,
                hash,
                parent_temporary_leaves_count,
            );

            /*if parent_temporary_leaves_count == (1 << current_height) {
                // all leaves in subtree are temporary, we can keep only subtree root
                self.remove_batched(batch, current_height - 1, child_index);
                self.remove_batched(batch, current_height - 1, second_child_index);
            }*/

            child_index = parent_index;
            child_hash = hash;
            child_temporary_leaves_count = parent_temporary_leaves_count;
        }
    }

    fn set_batched(
        &mut self,
        batch: &mut DBTransaction,
        height: u32,
        index: u64,
        hash: Hash<P::Fr>,
        temporary_leaves_count: u64,
    ) {
        let key = Self::node_key(height, index);
        batch.put(0, &key, &hash.try_to_vec().unwrap());
        if temporary_leaves_count > 0 {
            batch.put(1, &key, &temporary_leaves_count.to_be_bytes());
        }
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: u32, index: u64) {
        let key = Self::node_key(height, index);
        batch.delete(0, &key);
        batch.delete(1, &key);
    }

    fn get_temporary_count(&self, height: u32, index: u64) -> u64 {
        match self.get_temporary_count_opt(height, index) {
            Some(val) => val,
            _ => 0,
        }
    }

    fn get_temporary_count_opt(&self, height: u32, index: u64) -> Option<u64> {
        assert!(height <= constants::HEIGHT as u32);

        let key = Self::node_key(height, index);
        let res = self.db.get(1, &key);

        match res {
            Ok(Some(ref val)) => Some((&val[..]).read_u64::<BigEndian>().unwrap()),
            _ => None,
        }
    }

    #[inline]
    fn node_key(height: u32, index: u64) -> [u8; 12] {
        let mut data = [0u8; 12];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u32::<BigEndian>(height);
            let _ = bytes.write_u64::<BigEndian>(index);
        }

        data
    }

    fn parse_node_key(data: &[u8]) -> (u32, u64) {
        let mut bytes = data;
        let height = bytes.read_u32::<BigEndian>().unwrap();
        let index = bytes.read_u64::<BigEndian>().unwrap();

        (height, index)
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
}

#[derive(Debug)]
pub struct Node<F: PrimeField> {
    pub index: u64,
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
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use test_case::test_case;

    #[test]
    fn test_add_hashes_first_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());

        let hashes: Vec<_> = (0..3).map(|n| (n, rng.gen(), false)).collect();
        tree.add_hashes(hashes.clone());

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
        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());

        let max_index = (1 << constants::HEIGHT) - 1;
        let hashes: Vec<_> = (max_index - 2..=max_index)
            .map(|n| (n, rng.gen(), false))
            .collect();
        tree.add_hashes(hashes.clone());

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 3);

        for h in 0..constants::HEIGHT as u32 {
            let index = max_index / 2u64.pow(h);
            assert!(tree.get_opt(h, index).is_some()); // TODO: Compare with expected hash
        }

        for (i, tuple) in hashes.iter().enumerate() {
            assert_eq!(tree.get(0, tuple.0), hashes[i].1);
        }
    }

    #[test]
    fn test_unnecessary_temporary_nodes_are_removed() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());

        let mut hashes: Vec<_> = (0..6).map(|n| (n, rng.gen(), false)).collect();

        // make some hashes temporary
        // these two must remain after cleanup
        hashes[1].2 = true;
        hashes[3].2 = true;

        // these two must be removed
        hashes[4].2 = true;
        hashes[5].2 = true;

        tree.add_hashes(hashes);

        tree.clean();

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 6);
        assert_eq!(tree.get_opt(0, 4), None);
        assert_eq!(tree.get_opt(0, 5), None);
    }

    #[test]
    fn test_get_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());
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
        let mut tree_add_hashes = MerkleTree::new(create(2), POOL_PARAMS.clone());
        let mut tree_add_subtree = MerkleTree::new(create(2), POOL_PARAMS.clone());

        let hash_values: Vec<_> = (0..subtree_size).map(|_| rng.gen()).collect();
        let hashes = (0..subtree_size).map(|n| ((start_index + n) as u64, hash_values[n], false));

        tree_add_hashes.add_hashes(hashes);
        tree_add_subtree.add_subtree(&hash_values, start_index as u64);

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

    #[test]
    fn test_temporary_nodes_are_used_to_calculate_hashes_first() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());

        let hash0: Hash<_> = rng.gen();
        let hash1: Hash<_> = rng.gen();

        // add hash for index 0
        tree.add_hash(0, hash0.clone(), true);

        // add hash for index 1
        tree.add_hash(1, hash1.clone(), false);

        let parent_hash = tree.get(1, 0);
        let expected_parent_hash = poseidon([hash0, hash1].as_ref(), POOL_PARAMS.compress());

        assert_eq!(parent_hash, expected_parent_hash);
    }

    #[test_case(0, 5)]
    #[test_case(1, 5)]
    #[test_case(2, 5)]
    #[test_case(4, 5)]
    #[test_case(5, 5)]
    #[test_case(5, 8)]
    #[test_case(10, 15)]
    #[test_case(12, 15)]
    fn test_all_temporary_nodes_in_subtree_are_removed(subtree_height: u32, full_height: usize) {
        let mut rng = CustomRng;

        let subtree_size = 1 << subtree_height;
        let subtrees_count = (1 << full_height) / subtree_size;
        let start_index = 1 << 12;
        let mut subtree_indexes: Vec<_> = (0..subtrees_count).map(|i| start_index + i).collect();
        subtree_indexes.shuffle(&mut thread_rng());

        let mut tree = MerkleTree::new(create(2), POOL_PARAMS.clone());
        for subtree_index in subtree_indexes {
            tree.add_subtree_root(subtree_height, subtree_index, rng.gen());
        }

        tree.clean();

        let tree_nodes = tree.get_all_nodes();
        assert_eq!(
            tree_nodes.len(),
            constants::HEIGHT - full_height,
            "Some temporary subtree nodes were not removed."
        );
    }
}
