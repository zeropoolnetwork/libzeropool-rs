use libzeropool::native::params::{PoolBN256, PoolParams};
use wasm_bindgen::prelude::*;

pub type Fr = <PoolBN256 as PoolParams>::Fr;
pub type Fs = <PoolBN256 as PoolParams>::Fs;

#[wasm_bindgen(typescript_custom_section)]
const TS_APPEND_CONTENT: &'static str = r#"
export interface Note {
    d: string;
    p_d: string;
    b: string;
    t: string;
}

export interface Account {
    eta: string;
    i: string;
    b: string;
    e: string;
    t: string;
}

export interface Output {
    to: string;
    amount: string;
}

"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<Note>")]
    pub type Notes;

    #[wasm_bindgen(typescript_type = "Array<string>")]
    pub type MerkleProofSibling;

    #[wasm_bindgen(typescript_type = "Array<boolean>")]
    pub type MerkleProofPath;

    #[wasm_bindgen(typescript_type = "Array<Output>")]
    pub type TxOutputs;

    #[wasm_bindgen(typescript_type = "Note")]
    pub type Note;

    #[wasm_bindgen(typescript_type = "Account")]
    pub type Account;

    #[wasm_bindgen(typescript_type = "{ account: Account; notes: Array<Note> }")]
    pub type Pair;
}
