use std::convert::TryInto;
use std::str::FromStr;

use js_sys::Array;
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::params::{PoolBN256, PoolParams};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

// TODO: Don't convert fields to strings/buffers right away, do it on demand instead
// TODO: Add smart contract-ready serialization methods

pub type Fr = <PoolBN256 as PoolParams>::Fr;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<Note>")]
    pub type Notes;
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Note {
    inner: NativeNote<Fr>,
}

#[wasm_bindgen]
impl Note {
    #[wasm_bindgen(getter)]
    pub fn d(&self) -> String {
        self.inner.d.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn p_d(&self) -> String {
        self.inner.p_d.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn b(&self) -> String {
        self.inner.b.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn t(&self) -> String {
        self.inner.t.to_num().to_string()
    }
}

impl From<NativeNote<Fr>> for Note {
    fn from(note: NativeNote<Fr>) -> Note {
        Note { inner: note }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Account {
    inner: NativeAccount<Fr>,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(getter)]
    pub fn eta(&self) -> String {
        self.inner.eta.to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn i(&self) -> String {
        self.inner.i.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn b(&self) -> String {
        self.inner.b.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn e(&self) -> String {
        self.inner.e.to_num().to_string()
    }

    #[wasm_bindgen(getter)]
    pub fn t(&self) -> String {
        self.inner.t.to_num().to_string()
    }
}

impl From<NativeAccount<Fr>> for Account {
    fn from(account: NativeAccount<Fr>) -> Account {
        Account { inner: account }
    }
}

impl TryInto<NativeAccount<Fr>> for Account {
    type Error = <Fr as FromStr>::Err;

    fn try_into(self) -> Result<NativeAccount<Fr>, Self::Error> {
        Ok(self.inner)
    }
}

#[wasm_bindgen]
pub struct Pair {
    account: Account,
    notes: Vec<Note>,
}

impl Pair {
    pub fn new(account: Account, notes: Vec<Note>) -> Self {
        Pair { account, notes }
    }
}

#[wasm_bindgen]
impl Pair {
    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn notes(&self) -> Notes {
        self.notes
            .iter()
            .cloned()
            .map(JsValue::from)
            .collect::<Array>()
            .unchecked_into::<Notes>()
    }
}
