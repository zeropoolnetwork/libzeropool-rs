use std::collections::BTreeMap;
use std::marker::PhantomData;

use borsh::{BorshDeserialize, BorshSerialize};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database;
use libzeropool::constants;
use libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool::fawkes_crypto::native::poseidon::poseidon;
use libzeropool::native::note::Note;
use libzeropool::native::params::PoolParams;
use std::convert::TryInto;

type Hash<P: PoolParams> = Num<P::Fr>;

const DB_NAME: &str = "zeropool.smt";

// Key formats:
//   [node height]:[n] - hash
//   [n].data - element data
struct Smt<'p, P: PoolParams> {
    // TODO: Use abstract KeyValueDB instead
    db: Database,
    root: Hash<P>,
    num_elements: usize,
    params: &'p dyn PoolParams,
    default_hashes: Vec<Hash<P>>,
    _p: PhantomData<P>,
}

impl<'p, P: PoolParams> Smt<'p, P> {
    pub async fn new(params: &'p dyn PoolParams) -> Self {
        let mut default_hashes = vec![Num::ZERO; constants::H + 1];

        for i in 0..constants::H {
            let t = default_hashes[i];
            default_hashes[i + 1] = poseidon([t, t].as_ref(), params.compress());
        }

        Smt {
            db: Database::open(DB_NAME.to_owned(), 1).await.unwrap(),
            root: Num::ZERO,
            num_elements: 0,
            default_hashes,
            params,
            _p: Default::default(),
        }
    }

    /// Add a known note
    pub fn add_note(&mut self, note: Note<P>) {
        let mut batch = self.db.transaction();
        self.add_note_tx(&mut batch, note);
        self.db.write(batch).unwrap();
    }

    /// Add a hash of an unknown note
    pub fn add_hash(&mut self, hash: Hash<P>) {
        let mut batch = self.db.transaction();
        self.add_hash_tx(&mut batch, hash);
        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: usize, n: usize) -> Hash<P> {
        assert!(height <= constants::H);

        let key = format!("{}:{}", height, n);
        let res = self.db.get(o, key.as_bytes());

        match res {
            Ok(Some(val)) => val.try_into().unwrap(),
            _ => self.default_hashes[height],
        }
    }

    fn add_note_tx(&mut self, batch: &mut DBTransaction, note: Note<P>) {
        let key = format!("{}.data", self.num_elements);
        let value = note.try_to_vec().unwrap();
        batch.put(0, key.as_bytes(), &value);

        let hash = note.hash(self.params);
        self.add_hash_tx(batch, hash);
    }

    fn set(&self, height: usize, n: usize, hash: Hash<P>) {
        let key = format!("{}:{}", height, n);

        let mut batch = self.db.transaction();
        batch.put(0, key.as_bytes(), &hash);
        self.db.write(batch).unwrap();
    }

    fn add_hash_tx(&mut self, mut batch: &mut DBTransaction, hash: Hash<P>) {
        let key = format!("0:{}", self.num_elements);
        batch.put(0, key.as_bytes(), &hash);

        let mut hash = hash;
        for h in 1..constants::H {
            // FIXME
            let sibling = self.get(h, self.num_elements / 2.pow(h as u32));

            let parent = poseidon([hash, sibling].as_ref(), params.compress());

            self.set(h + 1, self.num_elements / 2.pow(h as u32 + 1), parent);
        }

        // TODO: Collect garbage

        self.num_elements += 1;
    }
}
