use std::cell::RefCell;
use std::rc::Rc;

use js_sys::{Array, Promise};
use kvdb_web::Database;
use libzeropool::{
    constants,
    fawkes_crypto::{
        ff_uint::Num,
        ff_uint::{NumRepr, Uint},
    },
    native::{
        account::Account as NativeAccount,
        boundednum::BoundedNum,
        note::Note as NativeNote,
        tx::{TransferPub as NativeTransferPub, TransferSec as NativeTransferSec},
    },
};
use libzeropool_rs::{
    client::{TxOutput, UserAccount as NativeUserAccount},
    merkle::Hash,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::future_to_promise;

use crate::{
    keys::reduce_sk, utils::Base64, Account, Fr, Fs, MerkleProof, Note, Notes, Pair, PoolParams,
    TxOutputs, UserState, POOL_PARAMS,
};

#[wasm_bindgen]
pub struct UserAccount {
    inner: Rc<RefCell<NativeUserAccount<Database, PoolParams>>>,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: &[u8], state: UserState) -> Result<UserAccount, JsValue> {
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
        crate::utils::set_panic_hook();

        let sk = reduce_sk(seed);
        Self::new(&sk, state)
    }

    #[wasm_bindgen(js_name = generateAddress)]
    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        crate::utils::set_panic_hook();

        self.inner.borrow().generate_address()
    }

    #[wasm_bindgen(js_name = decryptNotes)]
    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Result<Notes, JsValue> {
        crate::utils::set_panic_hook();

        let notes = self
            .inner
            .borrow()
            .decrypt_notes(data)
            .into_iter()
            .flatten()
            .map(|note| serde_wasm_bindgen::to_value(&note).unwrap())
            .collect::<Array>()
            .unchecked_into::<Notes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = decryptPair)]
    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        crate::utils::set_panic_hook();

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

    #[wasm_bindgen(js_name = "createTx")]
    /// Constructs a transaction.
    pub fn create_tx(&self, outputs: TxOutputs, data: Option<Vec<u8>>) -> Promise {
        crate::utils::set_panic_hook();

        #[derive(Deserialize)]
        struct Output {
            to: String,
            amount: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
        }

        #[derive(Serialize)]
        pub struct TransactionData {
            public: NativeTransferPub<Fr>,
            secret: NativeTransferSec<Fr>,
            ciphertext: Base64,
            memo: Base64,
        }

        // TODO: Signature callback

        let account = self.inner.clone();

        future_to_promise(async move {
            let js_outputs: JsValue = outputs.into();
            let outputs = serde_wasm_bindgen::from_value::<Vec<Output>>(js_outputs)?
                .into_iter()
                .map(|out| TxOutput {
                    to: out.to,
                    amount: out.amount,
                })
                .collect::<Vec<_>>();
            let tx = account
                .borrow()
                .create_tx(&outputs, data)
                .map(|tx| TransactionData {
                    public: tx.public,
                    secret: tx.secret,
                    ciphertext: Base64(tx.ciphertext),
                    memo: Base64(tx.memo),
                })
                .map_err(|err| js_err!("{}", err))?;

            Ok(serde_wasm_bindgen::to_value(&tx).unwrap())
        })
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account) -> Result<(), JsValue> {
        let account = serde_wasm_bindgen::from_value(account.into())?;
        self.inner.borrow_mut().add_account(at_index, account);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addReceivedNote")]
    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note) -> Result<(), JsValue> {
        let note = serde_wasm_bindgen::from_value(note.into())?;
        self.inner.borrow_mut().add_received_note(at_index, note);

        Ok(())
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.inner.borrow().total_balance().to_string()
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

    #[wasm_bindgen(js_name = "getMerkleProof")]
    /// Returns merkle proof for the specified index in the tree.
    pub fn get_merkle_proof(&self, index: u64) -> Option<MerkleProof> {
        self.inner
            .borrow()
            .state
            .tree
            .get_leaf_proof(index)
            .map(|proof| {
                serde_wasm_bindgen::to_value(&proof)
                    .unwrap()
                    .unchecked_into::<MerkleProof>()
            })
    }

    #[wasm_bindgen(js_name = "getMerkleProofAfter")]
    /// Returns merkle proofs for the specified leafs (hashes) as if they were appended to the tree.
    pub fn get_merkle_proof_after(&self, hashes: JsValue) -> Result<Vec<MerkleProof>, JsValue> {
        let hashes: Vec<Hash<Fr>> = serde_wasm_bindgen::from_value(hashes)?;

        let proofs = self
            .inner
            .borrow_mut()
            .state
            .tree
            .get_proof_after(hashes)
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
    pub fn get_commitment_merkle_proof(&self, index: u64) -> Option<MerkleProof> {
        let proof = self.inner.borrow().state.tree.get_commitment_proof(index)?;

        Some(
            serde_wasm_bindgen::to_value(&proof)
                .unwrap()
                .unchecked_into::<MerkleProof>(),
        )
    }
}
