use borsh::{BorshDeserialize, BorshSerialize};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use kvdb::{DBTransaction, KeyValueDB};
use kvdb_web::Database as WebDatabase;

use libzeropool::constants;
use libzeropool::fawkes_crypto::core::sizedvec::SizedVec;
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
    pub fn add_hash(&mut self, index: u32, hash: Hash<P::Fr>, retained: bool) {
        let mut batch = self.db.transaction();
        self.add_hash_batched(&mut batch, index, hash, retained);
        self.cleanup(&mut batch);
        self.db.write(batch).unwrap();
    }

    pub fn get(&self, height: u32, index: u32) -> Hash<P::Fr> {
        assert!(height <= constants::H as u32);

        let key = format!("{}:{}", height, index);
        let res = self.db.get(0, key.as_bytes());

        match res {
            Ok(Some(ref val)) => Hash::<P::Fr>::try_from_slice(val).unwrap(),
            _ => self.default_hashes[height as usize],
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

    pub fn get_proof(&self, index: u32) -> MerkleProof<P::Fr, { constants::H }> {
        // TODO: Add Default for SizedVec or make it's member public to replace all those iterators.
        let mut sibling: SizedVec<_, { constants::H }> =
            (0..constants::H).map(|_| Num::ZERO).collect();
        let mut path: SizedVec<_, { constants::H }> = (0..constants::H).map(|_| false).collect();

        sibling.iter_mut().zip(path.iter_mut()).enumerate().fold(
            index,
            |x, (h, (sibling, is_left))| {
                let h = h as u32;
                *is_left = x % 2 == 0;
                *sibling = self.get(h, x ^ 1);

                x / 2u32.pow(h as u32 + 1) ^ 1
            },
        );

        MerkleProof { sibling, path }
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
        retain: bool,
    ) {
        let hash_serialized = hash.try_to_vec().unwrap();

        Self::with_node_key(0, index, |key| {
            batch.put(0, &key, &hash_serialized);
        });

        if retain {
            // mark this hash as non-removable for later
            batch.put(0, format!("r:{}", index).as_bytes(), &hash_serialized);
        }

        // update inner nodes
        let mut hash = hash;
        for h in 1..constants::H as u32 {
            let pair = if index % 2 == 0 {
                [hash, self.get(h, index / 2u32.pow(h as u32))]
            } else {
                [self.get(h, index / 2u32.pow(h as u32) + 1), hash]
            };

            let parent = poseidon(pair.as_ref(), self.params.compress());
            hash = parent;

            self.set_batched(batch, h + 1, index / 2u32.pow(h as u32 + 1), parent);
        }
    }

    // TODO: Find a better way to serialize keys without allocation
    fn with_node_key<F: FnOnce(&[u8])>(height: u32, index: u32, func: F) {
        let mut data = [0u8; std::mem::size_of::<u32>() * 2 + 1];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u8(b'n');
            let _ = bytes.write_u32::<BigEndian>(height);
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        func(&data);
    }

    fn with_leaf_key<F: FnOnce(&[u8])>(index: u32, func: F) {
        let mut data = [0; std::mem::size_of::<u32>() + 1];
        {
            let mut bytes = &mut data[..];
            let _ = bytes.write_u8(b'l');
            let _ = bytes.write_u32::<BigEndian>(index);
        }

        func(&data);
    }

    fn cleanup(&mut self, batch: &mut DBTransaction) {
        let items_to_keep = self.db.iter_with_prefix(0, b"l");

        // get paths for all retained items
        let proofs = items_to_keep.map(|(k, _)| {
            let mut k_buf = &k[1..];
            let index = k_buf.read_u32::<BigEndian>().unwrap(); // FIXME: extract usize from key
            self.get_proof(index)
        });
    }
}

#[cfg(test)]
mod tests {}
