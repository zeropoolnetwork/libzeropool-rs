use kvdb_web::Database;
use libzeropool::{
    fawkes_crypto::{BorshDeserialize, BorshSerialize},
    native::{account::Account as NativeAccount, note::Note as NativeNote},
};
use libzeropool_rs::client::state::State;
use wasm_bindgen::{prelude::*, JsCast};

use crate::{
    ts_types::{Account, Note},
    utils, Fr, PoolParams, POOL_PARAMS,
};

#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug)]
pub enum Transaction {
    Account(NativeAccount<Fr>),
    Note(NativeNote<Fr>),
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

        let state = State::init_web(db_id, POOL_PARAMS.clone()).await;

        UserState { inner: state }
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account) -> Result<(), JsValue> {
        let native_account: NativeAccount<Fr> =
            serde_wasm_bindgen::from_value(account.unchecked_into())?;

        self.inner.add_account(at_index, native_account);

        Ok(())
    }

    #[wasm_bindgen(js_name = "addReceivedNote")]
    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note) -> Result<(), JsValue> {
        let native_note: NativeNote<_> = serde_wasm_bindgen::from_value(note.unchecked_into())?;

        self.inner.add_received_note(at_index, native_note);

        Ok(())
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
