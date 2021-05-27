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

const DB_NAME: &str = "zeropool.smt";

pub struct MerkleTree<'p, D: KeyValueDB, P: PoolParams> {
    db: D,
    params: &'p P,
    default_hashes: Vec<Hash<P::Fr>>,
}

impl<'p, P: PoolParams> MerkleTree<'p, WebDatabase, P> {
    pub async fn new_web(params: &'p P) -> MerkleTree<'p, WebDatabase, P> {
        let db = WebDatabase::open(DB_NAME.to_owned(), 1).await.unwrap();

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
        self.add_hash_batched(&mut batch, index, hash, temporary);
        self.cleanup(&mut batch);
        self.db.write(batch).unwrap();
    }

    /// Add multiple hashes from tuple (index, hash, temporary)
    pub fn add_hashes<'a, I>(&mut self, hashes: I)
    where
        I: IntoIterator<Item = &'a (u32, Hash<P::Fr>, bool)>,
        I::IntoIter: 'a,
        P::Fr: 'a,
    {
        let mut batch = self.db.transaction();

        for (index, hash, temporary) in hashes.into_iter().cloned() {
            self.add_hash_batched(&mut batch, index, hash, temporary);
        }

        self.db.write(batch).unwrap();

        let mut batch = self.db.transaction();
        self.cleanup(&mut batch);
        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: u32, index: u32) -> Hash<P::Fr> {
        match self.get_opt(height, index) {
            Some(val) => val,
            _ => self.default_hashes[height as usize],
        }
    }

    pub fn get_opt(&self, height: u32, index: u32) -> Option<Hash<P::Fr>> {
        assert!(height <= constants::H as u32);

        let res = Self::with_node_key(height, index, |key| self.db.get(0, key));

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

    pub fn remove_hash(&mut self, index: u32) {
        let hash = self.get(0, index);

        if hash == self.default_hashes[0] {
            return;
        }

        let mut batch = self.db.transaction();

        for h in 0..constants::H as u32 {
            self.remove_batched(&mut batch, h, index / 2u32.pow(h + 1));
        }

        self.db.write(batch).unwrap();
    }

    pub fn get_proof(&self, index: u32) -> Option<MerkleProof<P::Fr, { constants::H }>> {
        // TODO: Add Default for SizedVec or make it's member public to replace all those iterators.
        let leaf_present = Self::with_retained_node_key(index, |key| {
            self.db.get(0, key).map_or(false, |value| value.is_some())
        });

        if !leaf_present {
            return None;
        }

        let mut sibling: SizedVec<_, { constants::H }> =
            (0..constants::H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { constants::H }> = (0..constants::H).map(|_| false).collect();

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_left))| {
                let h = h as u32;
                *is_left = x % 2 == 0;
                *sibling = self.get(h, x ^ 1);

                (x as usize / 2usize.pow(h + 1) ^ 1) as u32
            },
        );

        Some(MerkleProof { sibling, path })
    }

    pub fn get_all_nodes(&self) -> Vec<Node<P::Fr>> {
        self.db
            .iter_with_prefix(0, b"n")
            .map(|(key, value)| {
                let mut key_buf = &key[1..];
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

    fn cleanup(&mut self, batch: &mut DBTransaction) {
        let mut used_hashes = HashSet::new(); // TODO: Preallocate?
        let permanent_hashes = self.db.iter_with_prefix(0, b"r");

        // Collect all used nodes
        for (key, value) in permanent_hashes {
            let value = Hash::<P::Fr>::try_from_slice(&value).unwrap();
            used_hashes.insert(value.to_uint());

            let mut key_buf = &key[1..];
            let index = key_buf.read_u32::<BigEndian>().unwrap();
            let proof = self.get_proof(index).unwrap(); // always present

            for hash in proof.sibling.iter() {
                used_hashes.insert(hash.to_uint());
            }
        } // FIXME: add the proof of the last hash

        // Remove unused
        let mut to_remove = Vec::new();
        for (key, value) in self.db.iter_with_prefix(0, b"n") {
            let value = Hash::<P::Fr>::try_from_slice(&value).unwrap();

            if !used_hashes.contains(&value.to_uint()) {
                let mut key_buf = &key[1..];
                let height = key_buf.read_u32::<BigEndian>().unwrap();
                let index = key_buf.read_u32::<BigEndian>().unwrap();

                to_remove.push((height, index));
            }
        }

        for (height, index) in to_remove {
            self.remove_batched(batch, height, index);
        }
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: u32, index: u32) {
        Self::with_node_key(height, index, |key| {
            batch.delete(0, key);
        });
    }

    fn set_batched(&self, batch: &mut DBTransaction, height: u32, index: u32, hash: Hash<P::Fr>) {
        Self::with_node_key(height, index, |key| {
            let hash = hash.try_to_vec().unwrap();
            batch.put(0, &key, &hash);
        });
    }

    fn add_hash_batched(
        &mut self,
        batch: &mut DBTransaction,
        index: u32,
        hash: Hash<P::Fr>,
        temporary: bool,
    ) {
        let hash_serialized = hash.try_to_vec().unwrap();

        Self::with_node_key(0, index, |key| {
            batch.put(0, &key, &hash_serialized);
        });

        if !temporary {
            // mark this hash as non-removable for later
            Self::with_retained_node_key(index, |key| {
                batch.put(0, key, &hash_serialized);
            });
        }

        // update inner nodes
        for h in 1..constants::H as u32 {
            let current_index = index / 2u32.pow(h);

            // get pair of children
            let child_left = current_index * 2;
            let pair = [self.get(h - 1, child_left), self.get(h - 1, child_left + 1)];
            let hash = poseidon(pair.as_ref(), self.params.compress());

            self.set_batched(batch, h, current_index, hash);
        }
    }

    // TODO: Find a better way to serialize keys without allocation
    fn with_node_key<R, F: FnOnce(&[u8]) -> R>(height: u32, index: u32, func: F) -> R {
        let mut data = [0u8; std::mem::size_of::<u32>() * 2 + 1];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u8(b'n');
            let _ = bytes.write_u32::<BigEndian>(height);
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        func(&data)
    }

    fn with_retained_node_key<R, F: FnOnce(&[u8]) -> R>(index: u32, func: F) -> R {
        let mut data = [0; std::mem::size_of::<u32>() + 1];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u8(b'r');
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        func(&data)
    }

    fn gen_default_hashes(params: &P) -> Vec<Hash<P::Fr>> {
        let zero = poseidon(&[Num::ZERO], params.compress());
        let mut default_hashes = vec![zero; constants::H];

        for i in 1..constants::H {
            let t = default_hashes[i - 1];
            default_hashes[i] = poseidon([t, t].as_ref(), params.compress());
        }

        default_hashes
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

    #[test]
    fn test_add_hashes_first_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(1), &*POOL_PARAMS);

        let hashes: Vec<_> = (0..3).map(|n| (n, rng.gen(), false)).collect();
        tree.add_hashes(&hashes);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::H + 3);

        for h in 0..constants::H as u32 {
            assert!(tree.get_opt(h, 0).is_some()); // TODO: Compare with expected hash
        }

        for (i, tuple) in hashes.iter().enumerate() {
            assert_eq!(tree.get(0, tuple.0), hashes[i].1);
        }
    }

    #[test]
    fn test_add_hashes_last_3() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(1), &*POOL_PARAMS);

        let hashes: Vec<_> = (u32::MAX - 2..=u32::MAX)
            .map(|n| (n, rng.gen(), false))
            .collect();
        tree.add_hashes(&hashes);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::H + 3);

        for h in 0..constants::H as u32 {
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
        let mut tree = MerkleTree::new(create(1), &*POOL_PARAMS);

        let mut hashes: Vec<_> = (0..6).map(|n| (n, rng.gen(), false)).collect();

        // make some hashes temporary
        // these two must remain after cleanup
        hashes[1].2 = true;
        hashes[3].2 = true;

        // these two must be removed
        hashes[4].2 = true;
        hashes[5].2 = true;

        tree.add_hashes(&hashes);

        let nodes = tree.get_all_nodes();
        assert_eq!(nodes.len(), constants::H + 6);
        assert_eq!(tree.get_opt(0, 4), None);
        assert_eq!(tree.get_opt(0, 5), None);
    }

    #[test]
    fn test_get_proof() {
        let mut rng = CustomRng;
        let mut tree = MerkleTree::new(create(1), &*POOL_PARAMS);
        let proof = tree.get_proof(123);

        assert!(proof.is_none());

        tree.add_hash(123, rng.gen(), false);
        let proof = tree.get_proof(123).unwrap();

        assert_eq!(proof.sibling.as_slice().len(), constants::H);
        assert_eq!(proof.path.as_slice().len(), constants::H);
    }
}
