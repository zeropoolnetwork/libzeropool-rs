use borsh::{BorshDeserialize, BorshSerialize};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database as WebDatabase;

use libzeropool::constants;
use libzeropool::fawkes_crypto::ff_uint::Num;
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
    pub async fn new(params: &'p P) -> MerkleTree<'p, WebDatabase, P> {
        let mut default_hashes = vec![Num::ZERO; constants::H];

        for i in 0..constants::H {
            let t = default_hashes[i];
            default_hashes[i + 1] = poseidon([t, t].as_ref(), params.compress());
        }

        let db = WebDatabase::open(DB_NAME.to_owned(), 1).await.unwrap();

        MerkleTree {
            db,
            default_hashes,
            params,
        }
    }
}

impl<'p, D: KeyValueDB, P: PoolParams> MerkleTree<'p, D, P> {
    pub fn add_hash(&mut self, index: usize, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();
        self.add_hash_batched(&mut batch, index, hash);
        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: usize, index: usize) -> Hash<P::Fr> {
        assert!(height <= constants::H);

        let key = format!("{}:{}", height, index);
        let res = self.db.get(0, key.as_bytes());

        match res {
            Ok(Some(ref val)) => Hash::<P::Fr>::try_from_slice(val).unwrap(),
            _ => self.default_hashes[height],
        }
    }

    pub fn set(&self, height: usize, index: usize, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();
        self.set_batched(&mut batch, height, index, hash);
        self.db.write(batch).unwrap();
    }

    pub fn remove_hash(&mut self, index: usize) {
        let hash = self.get(0, index);

        if hash == self.default_hashes[0] {
            return;
        }

        let mut batch = self.db.transaction();

        for h in 0..constants::H {
            self.remove_batched(&mut batch, h, index / 2usize.pow(h as u32 + 1));
        }

        self.db.write(batch).unwrap();
    }

    pub fn get_proof(&self, index: usize) -> MerkleProof<P::Fr, { constants::H }> {
        let mut siblings = Vec::with_capacity(constants::H);
        let mut path = Vec::with_capacity(constants::H);

        let mut index = index;
        for h in 0..constants::H {
            let is_left = index % 2 == 0;
            let sibling_index = index ^ 1;
            let sibling = self.get(h, sibling_index);

            path.push(is_left);
            siblings.push(sibling);

            index = index / 2usize.pow(h as u32 + 1) ^ 1;
        }

        MerkleProof {
            sibling: siblings.drain(..).collect(),
            path: path.drain(..).collect(),
        }
    }

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: usize, index: usize) {
        let key = Self::node_key(height, index);
        batch.delete(0, &key);
    }

    fn set_batched(
        &self,
        batch: &mut DBTransaction,
        height: usize,
        index: usize,
        hash: Hash<P::Fr>,
    ) {
        let key = Self::node_key(height, index);
        let hash = hash.try_to_vec().unwrap();
        batch.put(0, &key, &hash);
    }

    fn add_hash_batched(&mut self, batch: &mut DBTransaction, index: usize, hash: Hash<P::Fr>) {
        let key = Self::node_key(0, index);

        batch.put(0, &key, &hash.try_to_vec().unwrap());

        // update inner nodes
        let mut hash = hash;
        for h in 1..constants::H {
            let pair = if index % 2 == 0 {
                [hash, self.get(h, index / 2usize.pow(h as u32))]
            } else {
                [self.get(h, index / 2usize.pow(h as u32) + 1), hash]
            };

            let parent = poseidon(pair.as_ref(), self.params.compress());
            hash = parent;

            self.set_batched(batch, h + 1, index / 2usize.pow(h as u32 + 1), parent);
        }

        // TODO: Collect garbage
    }

    fn node_key(height: usize, index: usize) -> Vec<u8> {
        format!("{}:{}", height, index).into_bytes()
    }
}

#[cfg(test)]
mod tests {}
