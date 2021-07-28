use libzeropool::{
    fawkes_crypto::backend::bellman_groth16::engines::Bn256,
    native::params::{PoolBN256, PoolParams as NativePoolParams},
};
use wasm_bindgen::prelude::*;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as NativePoolParams>::Fr;
pub type Fs = <PoolParams as NativePoolParams>::Fs;
pub type Engine = Bn256;

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

export interface TransferPub {
    root: string;
    nullifier: string;
    out_commit: string;
    delta: string;
    memo: string;
}

export interface TransferPub {
    tx: Tx;
    in_proof: { account: MerkleProof; notes: Array<MerkleProof> };
    eddsa_s: string;
    eddsa_r: string;
    eddsa_a: string;
}

export interface Tx {
    input: { account: Account; notes: Array<Note> };
    output: { account: Account; notes: Array<Note> };
}

export interface Output {
    to: string;
    amount: string;
}

export interface MerkleProof {
    sibling: Array<string>;
    path: Array<boolean>;
}

export interface Proof {
    inputs: Array<string>;
    proof: SnarkProof;
}

export interface SnarkProof {
    a: [stirng, string];
    b: [[stirng, string], [stirng, string]];
    c: [stirng, string];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Array<Note>")]
    pub type Notes;

    #[wasm_bindgen(typescript_type = "MerkleProof")]
    pub type MerkleProof;

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

    #[wasm_bindgen(typescript_type = "TransferPub")]
    pub type TransferPub;

    #[wasm_bindgen(typescript_type = "TransferSec")]
    pub type TransferSec;

    #[wasm_bindgen(typescript_type = "Proof")]
    pub type Proof;

    #[wasm_bindgen(typescript_type = "SnarkProof")]
    pub type SnarkProof;
}
