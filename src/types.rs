use std::convert::TryInto;
use std::str::FromStr;

use libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::boundednum::BoundedNum;
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::params::PoolParams;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
#[derive(Clone)]
pub struct Note {
    d: String,
    pk_d: String,
    v: String,
    st: String,
}

#[wasm_bindgen]
impl Note {
    #[wasm_bindgen(getter)]
    pub fn d(&self) -> String {
        self.d.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn pk_d(&self) -> String {
        self.pk_d.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn v(&self) -> String {
        self.v.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn st(&self) -> String {
        self.st.clone()
    }
}

impl<P: PoolParams> From<NativeNote<P>> for Note {
    fn from(note: NativeNote<P>) -> Note {
        Note {
            d: note.d.to_num().to_string(),
            pk_d: note.pk_d.to_string(),
            v: note.v.to_num().to_string(),
            st: note.st.to_num().to_string(),
        }
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct Account {
    xsk: String,
    interval: String,
    v: String,
    e: String,
    st: String,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(getter)]
    pub fn xsk(&self) -> String {
        self.xsk.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn interval(&self) -> String {
        self.interval.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn v(&self) -> String {
        self.v.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn e(&self) -> String {
        self.e.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn st(&self) -> String {
        self.st.clone()
    }
}

impl<P: PoolParams> From<NativeAccount<P>> for Account {
    fn from(account: NativeAccount<P>) -> Account {
        Account {
            xsk: account.xsk.to_string(),
            interval: account.interval.to_num().to_string(),
            v: account.v.to_num().to_string(),
            e: account.e.to_num().to_string(),
            st: account.st.to_num().to_string(),
        }
    }
}

impl<P: PoolParams> TryInto<NativeAccount<P>> for Account {
    type Error = <P::Fr as FromStr>::Err;

    fn try_into(self) -> Result<NativeAccount<P>, Self::Error> {
        Ok(NativeAccount {
            xsk: Num::from_str(&self.xsk)?,
            interval: BoundedNum::new(Num::from_str(&self.interval)?),
            v: BoundedNum::new(Num::from_str(&self.v)?),
            e: BoundedNum::new(Num::from_str(&self.e)?),
            st: BoundedNum::new(Num::from_str(&self.st)?),
        })
    }
}

#[wasm_bindgen]
pub struct Pair {
    account: Account,
    note: Note,
}

#[wasm_bindgen]
impl Pair {
    pub fn new(account: Account, note: Note) -> Self {
        Pair { account, note }
    }

    #[wasm_bindgen(getter)]
    pub fn account(&self) -> Account {
        self.account.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn note(&self) -> Note {
        self.note.clone()
    }
}
