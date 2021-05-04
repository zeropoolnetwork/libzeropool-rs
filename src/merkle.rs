use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database;
use libzeropool::constants;
use libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool::fawkes_crypto::native::poseidon::poseidon;
use libzeropool::native::note::Note;
use libzeropool::native::params::PoolParams;

type Hash<F> = Num<F>;

const DB_NAME: &str = "zeropool.smt";

// Key formats:
//   [node height]:[n] - hash
//   note.[n] - element data
pub struct MerkleTree<'p, P: PoolParams> {
    // TODO: Use abstract KeyValueDB instead
    db: Database,
    num_elements: usize,
    params: &'p P,
    default_hashes: Vec<Hash<P::Fr>>,
    _p: PhantomData<P>,
}

impl<'p, P: PoolParams> MerkleTree<'p, P> {
    pub async fn new(params: &'p P) -> MerkleTree<'p, P> {
        let mut default_hashes = vec![Num::ZERO; constants::H];

        for i in 0..constants::H {
            let t = default_hashes[i];
            default_hashes[i + 1] = poseidon([t, t].as_ref(), params.compress());
        }

        MerkleTree {
            db: Database::open(DB_NAME.to_owned(), 1).await.unwrap(),
            num_elements: 0,
            default_hashes,
            params,
            _p: Default::default(),
        }
    }

    /// Add a known note
    pub fn add_note(&mut self, note: Note<P>) {
        let mut batch = self.db.transaction();
        self.add_note_batched(&mut batch, note);
        self.db.write(batch).unwrap();
    }

    /// Add a hash of an unknown note
    pub fn add_hash(&mut self, index: usize, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();
        self.add_hash_batched(&mut batch, index, hash);
        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: usize, n: usize) -> Hash<P::Fr> {
        assert!(height <= constants::H);

        let key = format!("{}:{}", height, n);
        let res = self.db.get(0, key.as_bytes());

        match res {
            Ok(Some(ref val)) => Hash::<P::Fr>::try_from_slice(val).unwrap(),
            _ => self.default_hashes[height],
        }
    }

    pub fn set(&self, height: usize, n: usize, hash: Hash<P::Fr>) {
        let mut batch = self.db.transaction();
        self.set_batched(&mut batch, height, n, hash);
        self.db.write(batch).unwrap();
    }

    pub fn remove_note(&mut self, index: usize) {
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

    fn remove_batched(&mut self, batch: &mut DBTransaction, height: usize, n: usize) {
        let key = Self::node_key(height, n);
        batch.delete(0, &key);
    }

    fn set_batched(&self, batch: &mut DBTransaction, height: usize, n: usize, hash: Hash<P::Fr>) {
        let key = Self::node_key(height, n);
        let hash = hash.try_to_vec().unwrap();
        batch.put(0, &key, &hash);
    }

    fn add_note_batched(&mut self, batch: &mut DBTransaction, note: Note<P>) {
        let key = format!("note.{}", self.num_elements);
        let value = note.try_to_vec().unwrap();
        batch.put(0, key.as_bytes(), &value);

        let hash = note.hash(self.params);
        self.add_hash_batched(batch, self.num_elements, hash);
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

        self.num_elements += 1;
    }

    fn node_key(height: usize, n: usize) -> Vec<u8> {
        format!("{}:{}", height, n).into_bytes()
    }
}
