use std::{convert::TryInto, ops::Deref, rc::Rc};

use kvdb::KeyValueDB;
use libzeropool::{
    constants,
    fawkes_crypto::{ff_uint::Num, ff_uint::PrimeField, BorshDeserialize, BorshSerialize},
    native::{
        account::Account, account::Account as NativeAccount, boundednum::BoundedNum, note::Note,
        note::Note as NativeNote, params::PoolParams,
    },
};

use crate::{merkle::MerkleTree, sparse_array::SparseArray};

pub type TxStorage<D, Fr> = SparseArray<D, Transaction<Fr>>;

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum Transaction<Fr: PrimeField> {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
}

pub struct State<D: KeyValueDB, P: PoolParams> {
    params: Rc<P>,
    pub(crate) tree: MerkleTree<D, P>,
    /// Stores only usable (own) accounts and notes
    pub(crate) txs: TxStorage<D, P::Fr>,
    pub(crate) latest_account: Option<NativeAccount<P::Fr>>,
    pub latest_account_index: u64,
    pub latest_note_index: u64,
    pub(crate) total_balance: BoundedNum<P::Fr, { constants::BALANCE_SIZE }>,
}

impl<D, P> State<D, P>
where
    D: KeyValueDB,
    P: PoolParams,
    P::Fr: 'static,
{
    pub fn new(merkle_db: D, txs_db: D, params: Rc<P>) -> Self {
        let tree = MerkleTree::new(merkle_db, params.clone());
        let txs = TxStorage::new(txs_db);

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
            params,
            tree,
            txs,
            latest_account_index,
            latest_note_index,
            latest_account,
            total_balance: BoundedNum::new(total_balance),
        }
    }

    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account<P::Fr>) {
        let account_hash = account.hash(self.params.deref());

        // Update tx storage
        self.txs.set(at_index, &Transaction::Account(account));

        // Update merkle tree
        self.tree.add_hash(at_index, account_hash, false);

        if at_index > self.latest_account_index {
            self.latest_account_index = at_index;
            self.latest_account = Some(account);
        }

        // Update balance
        self.total_balance = account.b;
    }

    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note<P::Fr>) {
        // Update tx storage
        self.txs.set(at_index, &Transaction::Note(note));

        // Update merkle tree
        let hash = note.hash(self.params.deref());
        self.tree.add_hash(at_index, hash, false);

        if at_index > self.latest_note_index {
            self.latest_note_index = at_index;
        }

        // Update balance
        self.total_balance = BoundedNum::new(self.total_balance.to_num() + note.b.to_num());
    }

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

    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> Num<P::Fr> {
        self.total_balance.to_num()
    }
}
