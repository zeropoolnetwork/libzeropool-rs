use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_memorydb::InMemory as MemoryDatabase;
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
use std::collections::HashMap;

pub type Hash<F> = Num<F>;

pub struct MerkleTree<D: KeyValueDB, P: PoolParams> {
    db: D,
    params: P,
    default_hashes: Vec<Hash<P::Fr>>,
    next_index: u64,
}

#[cfg(feature = "native")]
pub type NativeMerkleTree<P> = MerkleTree<NativeDatabase, P>;

#[cfg(feature = "web")]
pub type WebMerkleTree<P> = MerkleTree<WebDatabase, P>;

#[cfg(feature = "web")]
impl<P: PoolParams> MerkleTree<WebDatabase, P> {
    pub async fn new_web(name: &str, params: P) -> MerkleTree<WebDatabase, P> {
        let db = WebDatabase::open(name.to_owned(), 2).await.unwrap();

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

impl<P: PoolParams> MerkleTree<MemoryDatabase, P> {
    pub fn new_test(params: P) -> MerkleTree<MemoryDatabase, P> {
        Self::new(kvdb_memorydb::create(3), params)
    }
}

// TODO: Proper error handling.
impl<D: KeyValueDB, P: PoolParams> MerkleTree<D, P> {
    pub fn new(db: D, params: P) -> Self {
        // TODO: Optimize, this is extremely inefficient. Cache the number of leaves or ditch kvdb?
        let mut next_index = 0;
        for (k, _v) in db.iter(0) {
            let (height, index) = Self::parse_node_key(&k);

            if height == 0 && index > next_index {
                next_index = index + 1;
            }
        }

        MerkleTree {
            db,
            default_hashes: Self::gen_default_hashes(&params),
            params,
            next_index,
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

        if index >= self.next_index {
            self.next_index = index + 1;
        }
    }

    pub fn append_hash(&mut self, hash: Hash<P::Fr>, temporary: bool) -> u64 {
        let index = self.next_index;
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
        for (index_shift, &hash) in hashes.iter().enumerate() {
            // all leaves in subtree are permanent
            self.set_batched(&mut batch, 0, start_index + index_shift as u64, hash, 0);
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

    pub fn add_proof<const H: usize>(&mut self, index: u64, nodes: &[Hash<P::Fr>]) {
        let mut batch = self.db.transaction();

        let start_height = constants::HEIGHT - H;
        let mut tree_index = index;
        for (height, hash) in nodes.iter().enumerate() {
            // todo: check if it's correct to use temporary_leaves_count = 0
            self.set_batched(
                &mut batch,
                (start_height + height) as u32,
                tree_index ^ 1,
                *hash,
                0,
            );
            tree_index /= 2;
        }

        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: u32, index: u64) -> Hash<P::Fr> {
        match self.get_opt(height, index) {
            Some(val) => val,
            _ => self.default_hashes[height as usize],
        }
    }

    pub fn last_leaf(&self) -> Hash<P::Fr> {
        match self.get_opt(0, self.next_index.saturating_sub(1)) {
            Some(val) => val,
            _ => self.default_hashes[0],
        }
    }

    pub fn get_root(&self) -> Hash<P::Fr> {
        self.get(constants::HEIGHT as u32, 0)
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

    pub fn merkle_proof_root<const H: usize>(
        &self,
        leaf: Num<P::Fr>,
        proof: MerkleProof<P::Fr, { H }>,
    ) -> Num<P::Fr> {
        let root = proof
            .sibling
            .iter()
            .zip(proof.path.iter())
            .fold(leaf, |leaf, (s, p)| {
                let pair = if *p {
                    [s.clone(), leaf.clone()]
                } else {
                    [leaf.clone(), s.clone()]
                };
                poseidon(pair.as_ref(), self.params.compress())
            });
        root
    }

    pub fn get_proof_unchecked<const H: usize>(&self, index: u64) -> MerkleProof<P::Fr, { H }> {
        let mut sibling: SizedVec<_, { H }> = (0..H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { H }> = (0..H).map(|_| false).collect();

        let start_height = constants::HEIGHT - H;

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_right))| {
                let cur_height = (start_height + h) as u32;
                *is_right = x % 2 == 1;
                *sibling = self.get(cur_height, x ^ 1);

                x / 2
            },
        );

        MerkleProof { sibling, path }
    }

    pub fn get_leaf_proof(&self, index: u64) -> Option<MerkleProof<P::Fr, { constants::HEIGHT }>> {
        let key = Self::node_key(0, index);
        let node_present = self.db.get(0, &key).map_or(false, |value| value.is_some());
        if !node_present {
            return None;
        }
        Some(self.get_proof_unchecked(index))
    }

    pub fn get_commitment_proof(
        &self,
        index: u64,
    ) -> Option<MerkleProof<P::Fr, { constants::HEIGHT - constants::OUTPLUSONELOG }>> {
        let key = Self::node_key(constants::OUTPLUSONELOG as u32, index);
        let node_present = self.db.get(0, &key).map_or(false, |value| value.is_some());
        if !node_present {
            return None;
        }
        Some(self.get_proof_unchecked(index))
    }

    pub fn get_proof_after<I>(
        &mut self,
        new_hashes: I,
    ) -> Vec<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        // TODO: Optimize, no need to mutate the database.
        let index_offset = self.next_index;
        self.add_hashes(new_hashes.into_iter().enumerate().map(|(index, hash)| {
            let new_index = index_offset + index as u64;
            (new_index, hash, true)
        }));

        let proofs = (index_offset..self.next_index)
            .map(|index| {
                self.get_leaf_proof(index)
                    .expect("Leaf was expected to be present (bug)")
            })
            .collect();

        // FIXME: Not all nodes are deleted here
        for index in index_offset..self.next_index {
            self.remove_leaf(index);
        }

        proofs
    }

    pub fn get_proof_after_virtual<I>(
        &self,
        new_hashes: I,
    ) -> Vec<MerkleProof<P::Fr, { constants::HEIGHT }>>
    where
        I: IntoIterator<Item = Hash<P::Fr>>,
    {
        let index_offset = self.next_index;

        let mut virtual_nodes: HashMap<(u32, u64), Hash<P::Fr>> = new_hashes
            .into_iter()
            .enumerate()
            .map(|(index, hash)| ((0, index_offset + index as u64), hash))
            .collect();
        let new_hashes_count = virtual_nodes.len() as u64;

        (index_offset..index_offset + new_hashes_count)
            .map(|index| {
                self.get_proof_virtual(
                    index,
                    &mut virtual_nodes,
                    index_offset,
                    index_offset + new_hashes_count,
                )
            })
            .collect()
    }

    fn get_proof_virtual<const H: usize>(
        &self,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        new_hashes_left_index: u64,
        new_hashes_right_index: u64,
    ) -> MerkleProof<P::Fr, { H }> {
        let mut sibling: SizedVec<_, { H }> = (0..H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { H }> = (0..H).map(|_| false).collect();

        let start_height = constants::HEIGHT - H;

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_right))| {
                let cur_height = (start_height + h) as u32;
                *is_right = x % 2 == 1;
                *sibling = self.get_virtual_node(
                    cur_height,
                    x ^ 1,
                    virtual_nodes,
                    new_hashes_left_index,
                    new_hashes_right_index,
                );

                x / 2
            },
        );

        MerkleProof { sibling, path }
    }

    pub fn get_virtual_node(
        &self,
        height: u32,
        index: u64,
        virtual_nodes: &mut HashMap<(u32, u64), Hash<P::Fr>>,
        new_hashes_left_index: u64,
        new_hashes_right_index: u64,
    ) -> Hash<P::Fr> {
        let node_left = index * (1 << height);
        let node_right = (index + 1) * (1 << height);
        if node_right <= new_hashes_left_index || new_hashes_right_index <= node_left {
            return self.get(height, index);
        }

        let key = (height, index);
        match virtual_nodes.get(&key) {
            Some(hash) => *hash,
            None => {
                let left_child = self.get_virtual_node(
                    height - 1,
                    2 * index,
                    virtual_nodes,
                    new_hashes_left_index,
                    new_hashes_right_index,
                );
                let right_child = self.get_virtual_node(
                    height - 1,
                    2 * index + 1,
                    virtual_nodes,
                    new_hashes_left_index,
                    new_hashes_right_index,
                );
                let pair = [left_child, right_child];
                let hash = poseidon(pair.as_ref(), self.params.compress());
                virtual_nodes.insert(key, hash);

                hash
            }
        }
    }

    pub fn clean(&mut self) -> u64 {
        self.clean_before_index(u64::MAX)
    }

    pub fn clean_before_index(&mut self, clean_before_index: u64) -> u64 {
        let mut batch = self.db.transaction();

        // get all nodes
        // todo: improve performance?
        let keys: Vec<(u32, u64)> = self
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
            if (index + 1) * (1 << height) > clean_before_index {
                continue;
            }

            if self.subtree_contains_only_temporary_leaves(height, index) {
                // all leaves in subtree are temporary, we can keep only subtree root
                self.remove_batched(&mut batch, height - 1, 2 * index);
                self.remove_batched(&mut batch, height - 1, 2 * index + 1);
            }
        }

        self.set_clean_index_batched(&mut batch, clean_before_index);

        self.db.write(batch).unwrap();

        self.next_index
    }

    pub fn rollback(&mut self, rollback_index: u64) -> Option<u64> {
        let mut result: Option<u64> = None;

        // check that nodes that are necessary for rollback were not removed by clean
        let clean_index = self.get_clean_index();
        if rollback_index < clean_index {
            // find what nodes are missing
            let mut nodes_request_index = self.next_index;
            let mut index = rollback_index;
            for height in 0..constants::HEIGHT as u32 {
                let sibling_index = index ^ 1;
                if sibling_index < index
                    && !self.subtree_contains_only_temporary_leaves(height, sibling_index)
                {
                    let leaf_index = index * (1 << height);
                    if leaf_index < nodes_request_index {
                        nodes_request_index = leaf_index
                    }
                }
                index /= 2;
            }
            if nodes_request_index < clean_index {
                result = Some(nodes_request_index)
            }
        }

        // remove leaves
        for index in (rollback_index..self.next_index).rev() {
            self.remove_leaf(index);
        }

        self.next_index = rollback_index;

        result
    }

    pub fn get_all_nodes(&self) -> Vec<Node<P::Fr>> {
        self.db
            .iter(0)
            .map(|(key, value)| Self::build_node(&key, &value))
            .collect()
    }

    pub fn get_leaves(&self) -> Vec<Node<P::Fr>> {
        self.get_leaves_after(0)
    }

    pub fn get_leaves_after(&self, index: u64) -> Vec<Node<P::Fr>> {
        let prefix = (0u32).to_be_bytes();
        self.db
            .iter_with_prefix(0, &prefix)
            .map(|(key, value)| Self::build_node(&key, &value))
            .filter(|node| node.index >= index)
            .collect()
    }

    pub fn next_index(&self) -> u64 {
        self.next_index
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
        for current_height in height + 1..=constants::HEIGHT as u32 {
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
        if hash != self.default_hashes[height as usize] {
            batch.put(0, &key, &hash.try_to_vec().unwrap());
        } else {
            batch.delete(0, &key);
        }
        if temporary_leaves_count > 0 {
            batch.put(1, &key, &temporary_leaves_count.to_be_bytes());
        } else if self.db.has_key(1, &key).unwrap_or(false) {
            batch.delete(1, &key);
        }
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: u32, index: u64) {
        let key = Self::node_key(height, index);
        batch.delete(0, &key);
        batch.delete(1, &key);
    }

    fn remove_leaf(&mut self, index: u64) {
        let mut batch = self.db.transaction();

        self.remove_batched(&mut batch, 0, index);
        self.update_path_batched(&mut batch, 0, index, self.default_hashes[0], 0);

        self.db.write(batch).unwrap();
    }

    fn get_clean_index(&self) -> u64 {
        match self.get_named_index_opt("clean_index") {
            Some(val) => val,
            _ => 0,
        }
    }

    fn set_clean_index_batched(&mut self, batch: &mut DBTransaction, value: u64) {
        self.set_named_index_batched(batch, "clean_index", value);
    }

    fn get_named_index_opt(&self, key: &str) -> Option<u64> {
        let res = self.db.get(2, key.as_bytes());
        match res {
            Ok(Some(ref val)) => Some((&val[..]).read_u64::<BigEndian>().unwrap()),
            _ => None,
        }
    }

    fn set_named_index_batched(&mut self, batch: &mut DBTransaction, key: &str, value: u64) {
        batch.put(2, key.as_bytes(), &value.to_be_bytes());
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

    fn subtree_contains_only_temporary_leaves(&self, height: u32, index: u64) -> bool {
        self.get_temporary_count(height, index) == (1 << height)
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

    fn build_node(key: &[u8], value: &[u8]) -> Node<P::Fr> {
        let (height, index) = Self::parse_node_key(key);
        let value = Hash::try_from_slice(value).unwrap();

        Node {
            index,
            height,
            value,
        }
    }

    fn gen_default_hashes(params: &P) -> Vec<Hash<P::Fr>> {
        let mut default_hashes = vec![Num::ZERO; constants::HEIGHT + 1];

        for i in 1..=constants::HEIGHT {
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
    use libzeropool::constants::{HEIGHT, OUTPLUSONELOG};
    use libzeropool::fawkes_crypto::ff_uint::rand::Rng;
    use libzeropool::POOL_PARAMS;
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use test_case::test_case;

    #[test]
    fn test_add_hashes_first_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let hashes: Vec<_> = (0..3).map(|n| (n, rng.gen(), false)).collect();
        tree.add_hashes(hashes.clone());

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 4);

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
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let max_index = (1 << constants::HEIGHT) - 1;
        let hashes: Vec<_> = (max_index - 2..=max_index)
            .map(|n| (n, rng.gen(), false))
            .collect();
        tree.add_hashes(hashes.clone());

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 4);

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
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let mut hashes: Vec<_> = (0..6).map(|n| (n, rng.gen(), false)).collect();

        // make some hashes temporary
        // these two must remain after cleanup
        hashes[1].2 = true;
        hashes[3].2 = true;

        // these two must be removed
        hashes[4].2 = true;
        hashes[5].2 = true;

        tree.add_hashes(hashes);

        let next_index = tree.clean();
        assert_eq!(next_index, tree.next_index);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::HEIGHT + 7);
        assert_eq!(tree.get_opt(0, 4), None);
        assert_eq!(tree.get_opt(0, 5), None);
    }

    #[test]
    fn test_get_leaf_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let proof = tree.get_leaf_proof(123);

        assert!(proof.is_none());

        tree.add_hash(123, rng.gen(), false);
        let proof = tree.get_leaf_proof(123).unwrap();

        assert_eq!(proof.sibling.as_slice().len(), constants::HEIGHT);
        assert_eq!(proof.path.as_slice().len(), constants::HEIGHT);
    }

    #[test]
    fn test_get_proof_unchecked() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        // Get proof for the right child of the root of the tree
        const SUBROOT_HEIGHT: usize = 1;
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_eq!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.default_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );

        assert_eq!(proof.sibling.as_slice().len(), SUBROOT_HEIGHT);
        assert_eq!(proof.path.as_slice().len(), SUBROOT_HEIGHT);

        // If we add leaf to the right branch, then left child of the root should not change
        tree.add_hash(1 << 47, rng.gen(), false);
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_eq!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.default_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );

        // But if we add leaf to the left branch, then left child of the root should change
        tree.add_hash(1 << 47 - 1, rng.gen(), false);
        let proof = tree.get_proof_unchecked::<SUBROOT_HEIGHT>(1);
        assert_ne!(
            proof.sibling[SUBROOT_HEIGHT - 1],
            tree.default_hashes[constants::HEIGHT - SUBROOT_HEIGHT]
        );
    }

    #[test]
    fn test_merkle_proof_correct() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leaf1 = rng.gen();
        tree.add_hash(0, leaf1, false);
        let leaf2 = rng.gen();
        tree.add_hash(1, leaf2, false);

        let root = tree.get_root();

        let mp = tree.get_proof_unchecked::<HEIGHT>(0);
        let mp_root = tree.merkle_proof_root(leaf1, mp);

        assert_eq!(root, mp_root);

        let mp = tree.get_proof_unchecked::<HEIGHT>(1);
        let mp_root = tree.merkle_proof_root(leaf2, mp);

        assert_eq!(root, mp_root);

        let mp = tree.get_proof_unchecked::<{ HEIGHT - OUTPLUSONELOG }>(0);
        let mp_root = tree.merkle_proof_root(tree.get(OUTPLUSONELOG as u32, 0), mp);

        assert_eq!(root, mp_root);
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
        let mut tree_add_hashes = MerkleTree::new(create(3), POOL_PARAMS.clone());
        let mut tree_add_subtree = MerkleTree::new(create(3), POOL_PARAMS.clone());

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
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

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

        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());
        for subtree_index in subtree_indexes {
            tree.add_subtree_root(subtree_height, subtree_index, rng.gen());
        }

        tree.clean();

        let tree_nodes = tree.get_all_nodes();
        assert_eq!(
            tree_nodes.len(),
            constants::HEIGHT - full_height + 1,
            "Some temporary subtree nodes were not removed."
        );
    }

    #[test_case(32, 16)]
    #[test_case(0, 24)]
    #[test_case(16, 0)]
    #[test_case(11, 7)]
    fn test_rollback_removes_nodes_correctly(keep_size: u64, remove_size: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..keep_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }
        let original_root = tree.get_root();

        for index in keep_size..keep_size + remove_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let rollback_result = tree.rollback(keep_size);
        assert!(rollback_result.is_none());
        let rollback_root = tree.get_root();
        assert_eq!(rollback_root, original_root);
        assert_eq!(tree.next_index, keep_size)
    }

    #[test]
    fn test_rollback_works_correctly_after_clean() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..4 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }
        for index in 4..6 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }
        for index in 6..12 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }
        let original_root = tree.get_root();
        for index in 12..16 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        tree.clean_before_index(10);

        let rollback_result = tree.rollback(12);
        assert!(rollback_result.is_none());
        let rollback_root = tree.get_root();
        assert_eq!(rollback_root, original_root);
        assert_eq!(tree.next_index, 12)
    }

    #[test]
    fn test_rollback_of_cleaned_nodes() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..4 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }
        for index in 4..6 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }
        for index in 6..7 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }
        let original_root = tree.get_root();
        for index in 7..16 {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        tree.clean_before_index(10);

        let rollback_result = tree.rollback(7);
        assert_eq!(rollback_result.unwrap(), 6);
        let rollback_root = tree.get_root();
        assert_ne!(rollback_root, original_root);
        assert_eq!(tree.next_index, 7)
    }

    #[test]
    fn test_get_leaves() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leaves_count = 6;

        for index in 0..leaves_count {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        let leaves = tree.get_leaves();

        assert_eq!(leaves.len(), leaves_count as usize);
        for index in 0..leaves_count {
            assert!(leaves.iter().any(|node| node.index == index));
        }
    }

    #[test]
    fn test_get_leaves_after() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let leaves_count = 6;
        let skip_count = 2;

        for index in 0..leaves_count {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, true);
        }

        let leaves = tree.get_leaves_after(skip_count);

        assert_eq!(leaves.len(), (leaves_count - skip_count) as usize);
        for index in skip_count..leaves_count {
            assert!(leaves.iter().any(|node| node.index == index));
        }
    }

    #[test]
    fn test_get_proof_after() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let tree_size = 6;
        let new_hashes_size = 3;

        for index in 0..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let root_before_call = tree.get_root();

        let new_hashes: Vec<_> = (0..new_hashes_size).map(|_| rng.gen()).collect();
        tree.get_proof_after(new_hashes);

        let root_after_call = tree.get_root();

        assert_eq!(root_before_call, root_after_call);
    }

    #[test_case(12, 4)]
    #[test_case(13, 5)]
    #[test_case(0, 1)]
    #[test_case(0, 5)]
    #[test_case(0, 8)]
    #[test_case(4, 16)]
    fn test_get_proof_after_virtual(tree_size: u64, new_hashes_size: u64) {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        for index in 0..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        let new_hashes: Vec<_> = (0..new_hashes_size).map(|_| rng.gen()).collect();

        let root_before_call = tree.get_root();

        let proofs_virtual = tree.get_proof_after_virtual(new_hashes.clone());
        let proofs_simple = tree.get_proof_after(new_hashes.clone());

        let root_after_call = tree.get_root();

        assert_eq!(root_before_call, root_after_call);
        assert_eq!(proofs_simple.len(), proofs_virtual.len());
        for (simple_proof, virtual_proof) in proofs_simple.iter().zip(proofs_virtual) {
            for (simple_sibling, virtual_sibling) in simple_proof
                .sibling
                .iter()
                .zip(virtual_proof.sibling.iter())
            {
                assert_eq!(simple_sibling, virtual_sibling);
            }
            for (simple_path, virtual_path) in
                simple_proof.path.iter().zip(virtual_proof.path.iter())
            {
                assert_eq!(simple_path, virtual_path);
            }
        }
    }

    #[test]
    fn test_add_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(3), POOL_PARAMS.clone());

        let tree_size = 6;
        for index in 0..tree_size {
            let leaf = rng.gen();
            tree.add_hash(index, leaf, false);
        }

        // Leaf proofs
        let leaf_proofs_count = 3;
        for index in tree_size..tree_size + leaf_proofs_count {
            let proof_hashes: Vec<_> = (0..constants::HEIGHT).map(|_| rng.gen()).collect();
            tree.add_proof::<HEIGHT>(index, &proof_hashes);
            let tree_proof = tree.get_proof_unchecked::<HEIGHT>(index).sibling;

            assert_eq!(tree_proof.as_slice().len(), proof_hashes.len());
            for (actual_hash, expected_hash) in tree_proof.iter().zip(proof_hashes.iter()) {
                assert_eq!(actual_hash, expected_hash);
            }
        }

        // Commitment proofs
        let commitment_proofs_count = 3;
        for index in
            tree_size + leaf_proofs_count..tree_size + leaf_proofs_count + commitment_proofs_count
        {
            let proof_hashes: Vec<_> = (0..constants::HEIGHT - constants::OUTPLUSONELOG)
                .map(|_| rng.gen())
                .collect();
            tree.add_proof::<{ HEIGHT - OUTPLUSONELOG }>(index, &proof_hashes);
            let tree_proof = tree
                .get_proof_unchecked::<{ HEIGHT - OUTPLUSONELOG }>(index)
                .sibling;

            assert_eq!(tree_proof.as_slice().len(), proof_hashes.len());
            for (actual_hash, expected_hash) in tree_proof.iter().zip(proof_hashes.iter()) {
                assert_eq!(actual_hash, expected_hash);
            }
        }
    }
}
