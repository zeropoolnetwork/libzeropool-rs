use kvdb_web::Database;
use libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool::fawkes_crypto::{BorshDeserialize, BorshSerialize};
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::params::PoolBN256;
use libzeropool::POOL_PARAMS;
use wasm_bindgen::prelude::*;

use crate::sparse_array::SparseArray;
use crate::types::{Account, Fr, Note, Notes};
use std::convert::TryInto;

pub type MerkleTree = crate::merkle::MerkleTree<'static, Database, PoolBN256>;
pub type TxStorage = SparseArray<Database, Transaction>;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum Transaction {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
}

// TODO: Optimize:
//       Implement rev() for the kvdb iterator if possible.
//       Also consider finding a more efficient storage than kvdb since it clones the whole storage
//       when calling iter().
#[wasm_bindgen]
pub struct State {
    tree: MerkleTree,
    /// Stores only usable (own) accounts and notes
    txs: TxStorage,
    latest_account: Option<NativeAccount<Fr>>,
    pub latest_account_index: u32,
    pub latest_note_index: u32,
}

#[wasm_bindgen]
impl State {
    #[wasm_bindgen]
    pub async fn init(db_id: String) -> Self {
        let merkle_db_name = format!("zeropool.{}.smt", &db_id);
        let tx_db_name = format!("zeropool.{}.txs", &db_id);
        let tree = MerkleTree::new_web(&merkle_db_name, &POOL_PARAMS).await;
        let txs = TxStorage::new_web(&tx_db_name).await;

        let mut latest_account_index = 0;
        let mut latest_note_index = 0;
        let mut latest_account = None;
        for (index, tx) in txs.iter() {
            match tx {
                Transaction::Account(acc) => {
                    if index > latest_account_index {
                        latest_account_index = index;
                        latest_account = Some(acc);
                    }
                }
                Transaction::Note(_) => {
                    if index > latest_note_index {
                        latest_note_index = index;
                    }
                }
            }
        }

        State {
            tree,
            txs,
            latest_account_index,
            latest_note_index,
            latest_account,
        }
    }

    /// Cache account at specified index.
    #[wasm_bindgen(js_name = "addAccount")]
    pub fn add_account(&mut self, at_index: u32, account: Account) {
        let native_account: NativeAccount<Fr> = account.into();
        let account_hash: Num<Fr> = native_account.hash(&*POOL_PARAMS);
        let account = Transaction::Account(native_account);

        // Update tx storage
        self.txs.set(at_index, &account);

        // Update merkle tree
        self.tree.add_hash(at_index, account_hash, false);

        if at_index > self.latest_account_index {
            self.latest_account_index = at_index;
            self.latest_account = Some(native_account);
        }
    }

    /// Cache notes at specified index.
    #[wasm_bindgen(js_name = "addNotes")]
    pub fn add_notes(&mut self, at_index: u32, notes: Notes) {
        let notes: Vec<Note> = notes.into_serde().unwrap();

        // Update tx storage
        for (index, note) in notes.iter().enumerate() {
            let index = index as u32 + at_index;
            self.txs.set(index, &Transaction::Note(*note.inner()));
        }

        // Update merkle tree
        self.tree
            .add_hashes(notes.iter().enumerate().map(|(index, note)| {
                let hash = note.inner().hash(&*POOL_PARAMS);
                (at_index + index as u32, hash, false)
            }));

        let new_index = at_index + notes.len() as u32;
        if new_index > self.latest_note_index {
            self.latest_note_index = new_index;
        }
    }

    /// Return an index of the latest usable note.
    #[wasm_bindgen(js_name = "latestUsableIndex")]
    pub fn latest_usable_index(&self) -> u32 {
        self.latest_note_index
    }

    #[wasm_bindgen(js_name = "latestUsableIndex")]
    pub fn latest_account_index(&self) -> u32 {
        self.latest_account_index
    }

    /// Return an index of a earliest usable note.
    #[wasm_bindgen(js_name = "earliestUsableIndex")]
    pub fn earliest_usable_index(&self) -> u32 {
        let latest_account_index: u32 = self
            .latest_account
            .map(|acc| acc.i.to_num())
            .unwrap_or(Num::ZERO)
            .try_into()
            .unwrap();

        self.txs
            .iter_slice(latest_account_index..=self.latest_usable_index())
            .map(|(index, _)| index)
            .next()
            .unwrap_or(0)
    }
}

impl State {
    pub fn tree(&self) -> &MerkleTree {
        &self.tree
    }

    pub fn tree_mut(&mut self) -> &mut MerkleTree {
        &mut self.tree
    }

    pub fn txs(&self) -> &TxStorage {
        &self.txs
    }

    pub fn latest_account(&self) -> &Option<NativeAccount<Fr>> {
        &self.latest_account
    }
}
