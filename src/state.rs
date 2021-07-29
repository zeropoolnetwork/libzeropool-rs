use std::convert::TryInto;

use kvdb_web::Database;
use libzeropool::{
    constants,
    fawkes_crypto::{ff_uint::Num, BorshDeserialize, BorshSerialize},
    native::boundednum::BoundedNum,
    native::{account::Account as NativeAccount, note::Note as NativeNote, params::PoolBN256},
    POOL_PARAMS,
};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

use crate::{
    sparse_array::SparseArray,
    ts_types::{Account, Note},
    utils, Fr,
};

pub type MerkleTree = crate::merkle::MerkleTree<'static, Database, PoolBN256>;
pub type TxStorage = SparseArray<Database, Transaction>;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum Transaction {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
}

#[wasm_bindgen]
pub struct State {
    pub(crate) tree: MerkleTree,
    /// Stores only usable (own) accounts and notes
    pub(crate) txs: TxStorage,
    pub(crate) latest_account: Option<NativeAccount<Fr>>,
    #[wasm_bindgen(js_name = "latestAccountIndex")]
    pub latest_account_index: u64,
    #[wasm_bindgen(js_name = "latestNodeIndex")]
    pub latest_note_index: u64,
    pub(crate) total_balance: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
}

#[wasm_bindgen]
impl State {
    #[wasm_bindgen]
    pub async fn init(db_id: String) -> Self {
        utils::set_panic_hook();

        let merkle_db_name = format!("zeropool.{}.smt", &db_id);
        let tx_db_name = format!("zeropool.{}.txs", &db_id);
        let tree = MerkleTree::new_web(&merkle_db_name, &POOL_PARAMS).await;
        let txs = TxStorage::new_web(&tx_db_name).await;

        // TODO: Cache
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

        let mut total_balance = Num::ZERO;

        if let Some(account) = &latest_account {
            let account_i: u64 = account.i.to_num().try_into().unwrap();

            if account_i > latest_note_index {
                total_balance = account.b.to_num();
            } else {
                for (_, tx) in txs.iter_slice(account_i..=latest_note_index) {
                    if let Transaction::Note(note) = tx {
                        total_balance += note.b.to_num();
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
            total_balance: BoundedNum::new(total_balance),
        }
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account) -> Result<(), JsValue> {
        let native_account: NativeAccount<Fr> =
            serde_wasm_bindgen::from_value(account.unchecked_into())?;
        let account_hash: Num<Fr> = native_account.hash(&*POOL_PARAMS);

        // Update tx storage
        self.txs
            .set(at_index, &Transaction::Account(native_account));

        // Update merkle tree
        self.tree.add_hash(at_index, account_hash, false);

        if at_index > self.latest_account_index {
            self.latest_account_index = at_index;
            self.latest_account = Some(native_account);
        }

        // Update balance
        self.total_balance = native_account.b;

        Ok(())
    }

    #[wasm_bindgen(js_name = "addReceivedNote")]
    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note) -> Result<(), JsValue> {
        let note: NativeNote<_> = serde_wasm_bindgen::from_value(note.unchecked_into())?;

        // Update tx storage
        self.txs.set(at_index, &Transaction::Note(note));

        // Update merkle tree
        let hash = note.hash(&*POOL_PARAMS);
        self.tree.add_hash(at_index, hash, false);

        if at_index > self.latest_note_index {
            self.latest_note_index = at_index;
        }

        // Update balance
        self.total_balance = BoundedNum::new(self.total_balance.to_num() + note.b.to_num());

        Ok(())
    }

    #[wasm_bindgen(js_name = "earliestUsableIndex")]
    /// Return an index of a earliest usable note.
    pub fn earliest_usable_index(&self) -> u64 {
        let latest_account_index = self
            .latest_account
            .map(|acc| acc.i.to_num())
            .unwrap_or(Num::ZERO)
            .try_into()
            .unwrap();

        self.txs
            .iter_slice(latest_account_index..=self.latest_note_index)
            .map(|(index, _)| index)
            .next()
            .unwrap_or(0)
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.total_balance.to_num().to_string()
    }
}
