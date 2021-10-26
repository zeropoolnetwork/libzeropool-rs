use std::convert::TryInto;

use kvdb::KeyValueDB;
use kvdb_memorydb::InMemory as MemoryDatabase;
#[cfg(feature = "web")]
use kvdb_web::Database as WebDatabase;
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
    params: P,
    pub tree: MerkleTree<D, P>,
    /// Stores only usable (own) accounts and notes
    pub(crate) txs: TxStorage<D, P::Fr>,
    pub(crate) latest_account: Option<NativeAccount<P::Fr>>,
    pub latest_account_index: Option<u64>,
    /// Latest owned note index
    pub latest_note_index: u64,
    pub(crate) total_balance: BoundedNum<P::Fr, { constants::BALANCE_SIZE_BITS }>,
    account_balance: BoundedNum<P::Fr, { constants::BALANCE_SIZE_BITS }>,
    note_balance: BoundedNum<P::Fr, { constants::BALANCE_SIZE_BITS }>,
}

#[cfg(feature = "web")]
impl<P> State<WebDatabase, P>
where
    P: PoolParams,
    P::Fr: 'static,
{
    pub async fn init_web(db_id: String, params: P) -> Self {
        let merkle_db_name = format!("zeropool.{}.smt", &db_id);
        let tx_db_name = format!("zeropool.{}.txs", &db_id);
        let tree = MerkleTree::new_web(&merkle_db_name, params.clone()).await;
        let txs = TxStorage::new_web(&tx_db_name).await;

        Self::new(tree, txs, params)
    }
}

impl<P> State<MemoryDatabase, P>
where
    P: PoolParams,
    P::Fr: 'static,
{
    pub fn init_test(params: P) -> Self {
        let tree = MerkleTree::new_test(params.clone());
        let txs = TxStorage::new_test();

        Self::new(tree, txs, params)
    }
}

impl<D, P> State<D, P>
where
    D: KeyValueDB,
    P: PoolParams,
    P::Fr: 'static,
{
    pub fn new(tree: MerkleTree<D, P>, txs: TxStorage<D, P::Fr>, params: P) -> Self {
        // TODO: Cache
        let mut latest_account_index = None;
        let mut latest_note_index = 0;
        let mut latest_account = None;
        for (index, tx) in txs.iter() {
            match tx {
                Transaction::Account(acc) => {
                    if index >= latest_account_index.unwrap_or(0) {
                        latest_account_index = Some(index);
                        latest_account = Some(acc);
                    }
                }
                Transaction::Note(_) => {
                    if index >= latest_note_index {
                        latest_note_index = index;
                    }
                }
            }
        }

        let mut total_balance = Num::ZERO;
        let mut account_balance = Num::ZERO;
        let mut note_balance = Num::ZERO;

        let mut account_i = 0;
        if let Some(account) = &latest_account {
            account_i = account.i.to_num().try_into().unwrap();
            account_balance = account.b.to_num();
            total_balance = account.b.to_num();
        }

        for (_, tx) in txs.iter_slice(account_i..=latest_note_index) {
            if let Transaction::Note(note) = tx {
                total_balance += note.b.to_num();
                note_balance += note.b.to_num();
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
            account_balance: BoundedNum::new(account_balance),
            note_balance: BoundedNum::new(note_balance),
        }
    }

    /// Add OUT + 1 hashes to the tree
    pub fn add_hashes(&mut self, at_index: u64, hashes: &[Num<P::Fr>]) {
        // FIXME: return an error instead of asserts
        assert_eq!(
            at_index % (constants::OUT as u64 + 1),
            0,
            "index must be divisible by {}",
            constants::OUT + 1
        );

        assert_eq!(
            hashes.len(),
            constants::OUT + 1,
            "Number of hashes must be equal to {} (number of outputs)",
            constants::OUT + 1
        );

        // Update the tree
        for (index, hash) in hashes.iter().cloned().enumerate() {
            self.tree.add_hash(at_index + index as u64, hash, false);
        }
    }

    /// Add hashes, account, and notes to state
    pub fn add_full_tx(
        &mut self,
        at_index: u64,
        hashes: &[Num<P::Fr>],
        account: Option<Account<P::Fr>>,
        notes: &[(u64, Note<P::Fr>)],
    ) {
        self.add_hashes(at_index, hashes);

        if let Some(acc) = account {
            self.add_account(at_index, acc);

            if at_index >= self.latest_account_index.unwrap_or(0) {
                self.latest_account_index = Some(at_index);
                self.latest_account = Some(acc);
            }
        }

        // Store notes
        for (index, note) in notes {
            self.add_note(*index, *note);
        }
    }

    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account<P::Fr>) {
        // Update tx storage
        self.txs.set(at_index, &Transaction::Account(account));

        if at_index >= self.latest_account_index.unwrap_or(0) {
            self.latest_account_index = Some(at_index);
            self.latest_account = Some(account);
        }

        // Update balance
        let account_i: u64 = account.i.to_num().try_into().unwrap();
        if account_i >= self.latest_note_index {
            self.total_balance = account.b;
            self.account_balance = account.b;
        }
    }

    /// Caches a note at specified index.
    pub fn add_note(&mut self, at_index: u64, note: Note<P::Fr>) {
        if self.txs.get(at_index).is_some() {
            return;
        }

        self.txs.set(at_index, &Transaction::Note(note));
        self.total_balance = BoundedNum::new(self.total_balance.to_num() + note.b.to_num());

        if at_index > self.latest_note_index {
            self.latest_note_index = at_index;
            self.note_balance = BoundedNum::new(self.note_balance.to_num() + note.b.to_num());
        }
    }

    pub fn get_all_txs(&self) -> Vec<(u64, Transaction<P::Fr>)> {
        self.txs.iter().collect()
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

    pub fn account_balance(&self) -> Num<P::Fr> {
        self.account_balance.to_num()
    }
    pub fn note_balance(&self) -> Num<P::Fr> {
        self.note_balance.to_num()
    }
}
