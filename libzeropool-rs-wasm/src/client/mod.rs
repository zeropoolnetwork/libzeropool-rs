use std::{cell::RefCell, collections::HashMap, convert::TryInto, rc::Rc};

use js_sys::Array;
use libzeropool_rs::{
    client::{StateFragment, TxType as NativeTxType, UserAccount as NativeUserAccount},
    libzeropool::{
        constants,
        fawkes_crypto::{
            borsh::BorshDeserialize,
            core::sizedvec::SizedVec,
            ff_uint::{Num, NumRepr, Uint},
        },
        native::{
            account::Account as NativeAccount,
            note::Note as NativeNote,
            tx::{parse_delta, TransferPub as NativeTransferPub, TransferSec as NativeTransferSec},
        },
    },
    merkle::{Hash, Node},
};
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use wasm_bindgen::{prelude::*, JsCast};

use crate::{
    database::Database, keys::reduce_sk, ts_types::Hash as JsHash, Account, Fr, Fs, Hashes,
    IDepositData, IDepositPermittableData, ITransferData, IWithdrawData, IndexedNote, IndexedNotes,
    MerkleProof, Pair, PoolParams, Transaction, TransactionData, UserState, POOL_PARAMS,
};

mod tx_types;
use tx_types::JsTxType;

use self::tx_parser::StateUpdate;

mod tx_parser;

// TODO: Find a way to expose MerkleTree,

#[derive(Serialize)]
pub struct ParsedDelta {
    pub v: String,
    pub e: String,
    pub index: String,
    pub pool_id: String,
}

#[derive(Serialize)]
struct TransactionDataSer {
    public: NativeTransferPub<Fr>,
    secret: NativeTransferSec<Fr>,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    memo: Vec<u8>,
    commitment_root: Num<Fr>,
    out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
    parsed_delta: ParsedDelta,
}

#[wasm_bindgen]
pub struct UserAccount {
    inner: Rc<RefCell<NativeUserAccount<Database, PoolParams>>>,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: &[u8], state: UserState) -> Result<UserAccount, JsValue> {
        crate::utils::set_panic_hook();

        let sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid spending key"))?;
        let account = NativeUserAccount::new(sk, state.inner, POOL_PARAMS.clone());

        Ok(UserAccount {
            inner: Rc::new(RefCell::new(account)),
        })
    }

    // TODO: Is this safe?
    #[wasm_bindgen(js_name = fromSeed)]
    /// Same as constructor but accepts arbitrary data as spending key.
    pub fn from_seed(seed: &[u8], state: UserState) -> Result<UserAccount, JsValue> {
        let sk = reduce_sk(seed);
        Self::new(&sk, state)
    }

    #[wasm_bindgen(js_name = generateAddress)]
    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        self.inner.borrow().generate_address()
    }

    #[wasm_bindgen(js_name = decryptNotes)]
    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Result<IndexedNotes, JsValue> {
        let notes = self
            .inner
            .borrow()
            .decrypt_notes(data)
            .into_iter()
            .enumerate()
            .filter_map(|(index, note)| {
                let note = IndexedNote {
                    index: index as u64,
                    note: note?,
                };

                Some(serde_wasm_bindgen::to_value(&note).unwrap())
            })
            .collect::<Array>()
            .unchecked_into::<IndexedNotes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = decryptPair)]
    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        #[derive(Serialize)]
        struct SerPair {
            account: NativeAccount<Fr>,
            notes: Vec<NativeNote<Fr>>,
        }

        let pair = self
            .inner
            .borrow()
            .decrypt_pair(data)
            .map(|(account, notes)| {
                let pair = SerPair { account, notes };

                serde_wasm_bindgen::to_value(&pair)
                    .unwrap()
                    .unchecked_into::<Pair>()
            });

        Ok(pair)
    }

    fn construct_tx_data(
        &self,
        native_tx: NativeTxType<Fr>,
        new_state: Option<StateUpdate>,
    ) -> Result<TransactionData, JsValue> {
        let account = self.inner.clone();

        let extra_state = new_state.map(|s| {
            let mut joined_notes = vec![];
            s.new_notes.into_iter().for_each(|notes| {
                notes.into_iter().for_each(|one_note| {
                    joined_notes.push(one_note);
                });
            });

            StateFragment {
                new_leafs: s.new_leafs,
                new_commitments: s.new_commitments,
                new_accounts: s.new_accounts,
                new_notes: joined_notes,
            }
        });

        let tx = account
            .borrow()
            .create_tx(native_tx, None, extra_state)
            .map_err(|err| js_err!("{}", err))?;

        let (v, e, index, pool_id) = parse_delta(tx.public.delta);
        let parsed_delta = {
            let v: i64 = v.try_into().unwrap();
            let e: i64 = e.try_into().unwrap();

            ParsedDelta {
                v: v.to_string(),
                e: e.to_string(),
                index: index.to_string(),
                pool_id: pool_id.to_string(),
            }
        };

        let tx = TransactionDataSer {
            public: tx.public,
            secret: tx.secret,
            ciphertext: tx.ciphertext,
            memo: tx.memo,
            out_hashes: tx.out_hashes,
            commitment_root: tx.commitment_root,
            parsed_delta,
        };

        let serializer = Serializer::new().serialize_large_number_types_as_bigints(true);
        let value: JsValue = tx.serialize(&serializer).unwrap();

        Ok(value.unchecked_into::<TransactionData>())
    }

    #[wasm_bindgen(js_name = "createDeposit")]
    pub fn create_deposit(&self, deposit: IDepositData) -> Result<TransactionData, JsValue> {
        self.construct_tx_data(deposit.to_native()?, None)
    }

    #[wasm_bindgen(js_name = "createDepositOptimistic")]
    pub fn create_deposit_optimistic(
        &self,
        deposit: IDepositData,
        new_state: JsValue,
    ) -> Result<TransactionData, JsValue> {
        let new_state: StateUpdate =
            serde_wasm_bindgen::from_value(new_state).map_err(|err| js_err!(&err.to_string()))?;
        self.construct_tx_data(deposit.to_native()?, Some(new_state))
    }

    #[wasm_bindgen(js_name = "createDepositPermittable")]
    pub fn create_deposit_permittable(
        &self,
        deposit: IDepositPermittableData,
    ) -> Result<TransactionData, JsValue> {
        self.construct_tx_data(deposit.to_native()?, None)
    }

    #[wasm_bindgen(js_name = "createTransfer")]
    pub fn create_transfer(&self, transfer: ITransferData) -> Result<TransactionData, JsValue> {
        self.construct_tx_data(transfer.to_native()?, None)
    }

    #[wasm_bindgen(js_name = "createTransferOptimistic")]
    pub fn create_transfer_optimistic(
        &self,
        transfer: ITransferData,
        new_state: JsValue,
    ) -> Result<TransactionData, JsValue> {
        let new_state: StateUpdate =
            serde_wasm_bindgen::from_value(new_state).map_err(|err| js_err!(&err.to_string()))?;
        self.construct_tx_data(transfer.to_native()?, Some(new_state))
    }

    #[wasm_bindgen(js_name = "createWithdraw")]
    pub fn create_withdraw(&self, withdraw: IWithdrawData) -> Result<TransactionData, JsValue> {
        self.construct_tx_data(withdraw.to_native()?, None)
    }

    #[wasm_bindgen(js_name = "createWithdrawalOptimistic")]
    pub fn create_withdraw_optimistic(
        &self,
        withdraw: IWithdrawData,
        new_state: JsValue,
    ) -> Result<TransactionData, JsValue> {
        let new_state: StateUpdate =
            serde_wasm_bindgen::from_value(new_state).map_err(|err| js_err!(&err.to_string()))?;
        self.construct_tx_data(withdraw.to_native()?, Some(new_state))
    }

    #[wasm_bindgen(js_name = "isOwnAddress")]
    pub fn is_own_address(&self, address: &str) -> bool {
        self.inner.borrow().is_own_address(address)
    }

    #[wasm_bindgen(js_name = "addCommitment")]
    /// Add out commitment hash to the tree.
    pub fn add_commitment(&mut self, index: u64, commitment: Vec<u8>) -> Result<(), JsValue> {
        self.inner.borrow_mut().state.tree.add_hash_at_height(
            constants::OUTPLUSONELOG as u32,
            index,
            Num::try_from_slice(commitment.as_slice()).unwrap(),
            false,
        );

        Ok(())
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account and notes (own tx) at specified index.
    pub fn add_account(
        &mut self,
        at_index: u64,
        hashes: Hashes,
        account: Account,
        notes: IndexedNotes,
    ) -> Result<(), JsValue> {
        let account = serde_wasm_bindgen::from_value(account.into())?;
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;
        let notes: Vec<_> =
            serde_wasm_bindgen::from_value::<Vec<IndexedNote>>(notes.unchecked_into())?
                .into_iter()
                .map(|note| (note.index, note.note))
                .collect();

        self.inner
            .borrow_mut()
            .state
            .add_full_tx(at_index, &hashes, account, &notes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addHashes")]
    /// Cache tx hashes at specified index.
    pub fn add_hashes(&mut self, at_index: u64, hashes: Hashes) -> Result<(), JsValue> {
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;

        self.inner.borrow_mut().state.add_hashes(at_index, &hashes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addNotes")]
    /// Cache only notes at specified index
    pub fn add_notes(
        &mut self,
        at_index: u64,
        hashes: Hashes,
        notes: IndexedNotes,
    ) -> Result<(), JsValue> {
        let hashes: Vec<_> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;
        let notes: Vec<_> =
            serde_wasm_bindgen::from_value::<Vec<IndexedNote>>(notes.unchecked_into())?
                .into_iter()
                .map(|note| (note.index, note.note))
                .collect();

        self.inner
            .borrow_mut()
            .state
            .add_full_tx(at_index, &hashes, None, &notes);

        Ok(())
    }

    #[wasm_bindgen(js_name = "updateState")]
    pub fn update_state(&mut self, state_update: JsValue) -> Result<(), JsValue> {
        let state_update: StateUpdate = serde_wasm_bindgen::from_value(state_update)
            .map_err(|err| js_err!(&err.to_string()))?;

        if !state_update.new_leafs.is_empty() || !state_update.new_commitments.is_empty() {
            self.inner
                .borrow_mut()
                .state
                .tree
                .add_leafs_and_commitments(state_update.new_leafs, state_update.new_commitments);
        }

        state_update
            .new_accounts
            .into_iter()
            .for_each(|(at_index, account)| {
                self.inner.borrow_mut().state.add_account(at_index, account);
            });

        state_update.new_notes.into_iter().for_each(|notes| {
            notes.into_iter().for_each(|(at_index, note)| {
                self.inner.borrow_mut().state.add_note(at_index, note);
            });
        });

        Ok(())
    }

    #[wasm_bindgen(js_name = "getRoot")]
    pub fn get_root(&mut self) -> String {
        let root = self.inner.borrow_mut().state.tree.get_root().to_string();

        root
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.inner.borrow().state.total_balance().to_string()
    }

    #[wasm_bindgen(js_name = "accountBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn account_balance(&self) -> String {
        self.inner.borrow().state.account_balance().to_string()
    }

    #[wasm_bindgen(js_name = "noteBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn note_balance(&self) -> String {
        self.inner.borrow().state.note_balance().to_string()
    }

    #[wasm_bindgen(js_name = "getUsableNotes")]
    /// Returns all notes available for spending
    pub fn get_usable_notes(&self) -> JsValue {
        let data = self.inner.borrow().state.get_usable_notes();

        serde_wasm_bindgen::to_value(&data).unwrap()
    }

    #[wasm_bindgen(js_name = "nextTreeIndex")]
    pub fn next_tree_index(&self) -> u64 {
        self.inner.borrow().state.tree.next_index()
    }

    // TODO: Temporary method, try to expose the whole tree
    #[wasm_bindgen(js_name = "getLastLeaf")]
    pub fn get_last_leaf(&self) -> String {
        self.inner.borrow().state.tree.last_leaf().to_string()
    }

    #[wasm_bindgen(js_name = "getMerkleNode")]
    pub fn get_merkle_node(&self, height: u32, index: u64) -> String {
        let node = self.inner.borrow().state.tree.get(height, index);

        node.to_string()
    }

    #[wasm_bindgen(js_name = "getMerkleProof")]
    /// Returns merkle proof for the specified index in the tree.
    pub fn get_merkle_proof(&self, index: u64) -> MerkleProof {
        let proof = self
            .inner
            .borrow()
            .state
            .tree
            .get_proof_unchecked::<{ constants::HEIGHT }>(index);

        serde_wasm_bindgen::to_value(&proof)
            .unwrap()
            .unchecked_into::<MerkleProof>()
    }

    // TODO: This is a temporary method
    #[wasm_bindgen(js_name = "getMerkleRootAfterCommitment")]
    pub fn get_merkle_root_after_commitment(
        &self,
        commitment_index: u64,
        commitment: JsHash,
    ) -> Result<String, JsValue> {
        let hash: Hash<Fr> = serde_wasm_bindgen::from_value(commitment.unchecked_into())?;
        let mut nodes = HashMap::new();
        nodes.insert((constants::OUTPLUSONELOG as u32, commitment_index), hash);

        let left_index = commitment_index * (2u64.pow(constants::OUTPLUSONELOG as u32));
        let node = self.inner.borrow().state.tree.get_virtual_node(
            constants::HEIGHT as u32,
            0,
            &mut nodes,
            left_index,
            left_index + constants::OUT as u64 + 1,
        );

        Ok(node.to_string())
    }

    #[wasm_bindgen(js_name = "getMerkleProofAfter")]
    /// Returns merkle proofs for the specified leafs (hashes) as if they were appended to the tree.
    pub fn get_merkle_proof_after(&self, hashes: Hashes) -> Result<Vec<MerkleProof>, JsValue> {
        let hashes: Vec<Hash<Fr>> = serde_wasm_bindgen::from_value(hashes.unchecked_into())?;

        let proofs = self
            .inner
            .borrow_mut()
            .state
            .tree
            .get_proof_after_virtual(hashes)
            .into_iter()
            .map(|proof| {
                serde_wasm_bindgen::to_value(&proof)
                    .unwrap()
                    .unchecked_into::<MerkleProof>()
            })
            .collect();

        Ok(proofs)
    }

    #[wasm_bindgen(js_name = "getCommitmentMerkleProof")]
    pub fn get_commitment_merkle_proof(&self, index: u64) -> MerkleProof {
        let proof = self
            .inner
            .borrow()
            .state
            .tree
            .get_proof_unchecked::<{ constants::HEIGHT - constants::OUTPLUSONELOG }>(index);

        serde_wasm_bindgen::to_value(&proof)
            .unwrap()
            .unchecked_into::<MerkleProof>()
    }

    #[wasm_bindgen(js_name = "getWholeState")]
    pub fn get_whole_state(&self) -> JsValue {
        #[derive(Serialize)]
        struct WholeState {
            nodes: Vec<Node<Fr>>,
            txs: Vec<(u64, Transaction)>,
        }

        let state = &self.inner.borrow().state;
        let nodes = state.tree.get_all_nodes();
        let txs = state
            .get_all_txs()
            .into_iter()
            .map(|(i, tx)| (i, tx.into()))
            .collect();

        let data = WholeState { nodes, txs };

        serde_wasm_bindgen::to_value(&data).unwrap()
    }

    #[wasm_bindgen(js_name = "rollback")]
    pub fn rollback(&mut self, index: u64) {
        self.inner.borrow_mut().state.rollback(index);
    }
}
