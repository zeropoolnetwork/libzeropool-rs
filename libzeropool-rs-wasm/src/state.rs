use libzeropool::{
    fawkes_crypto::{BorshDeserialize, BorshSerialize},
    native::{account::Account as NativeAccount, note::Note as NativeNote},
};
use libzeropool_rs::client::state::{State, Transaction as InnerTransaction};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

use crate::database::Database;
use crate::{utils, Fr, PoolParams, POOL_PARAMS};

#[derive(Debug, PartialEq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub enum Transaction {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
}

impl From<InnerTransaction<Fr>> for Transaction {
    fn from(other: InnerTransaction<Fr>) -> Self {
        match other {
            InnerTransaction::Account(acc) => Transaction::Account(acc),
            InnerTransaction::Note(note) => Transaction::Note(note),
        }
    }
}

#[wasm_bindgen]
pub struct UserState {
    #[wasm_bindgen(skip)]
    pub inner: State<Database, PoolParams>,
}

#[wasm_bindgen]
impl UserState {
    #[wasm_bindgen]
    pub async fn init(db_id: String) -> Self {
        utils::set_panic_hook();

        #[cfg(any(feature = "bundler", feature = "web"))]
        let state = State::init_web(db_id, POOL_PARAMS.clone()).await;

        #[cfg(not(any(feature = "bundler", feature = "web")))]
        let state = State::init_test(POOL_PARAMS.clone());

        UserState { inner: state }
    }

    #[wasm_bindgen(js_name = "earliestUsableIndex")]
    /// Return an index of a earliest usable note.
    pub fn earliest_usable_index(&self) -> u64 {
        self.inner.earliest_usable_index()
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.inner.total_balance().to_string()
    }
}
