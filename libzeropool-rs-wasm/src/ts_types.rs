use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const TS_TYPES: &'static str = r#"
export class Constants {
  HEIGHT: number;
  IN: number;
  OUT: number;
  OUTLOG: number;
}

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

export interface TransferSec {
    tx: Tx;
    in_proof: { account: MerkleProof; notes: Array<MerkleProof> };
    eddsa_s: string;
    eddsa_r: string;
    eddsa_a: string;
}

export interface TransactionData {
    public: TransferPub;
    secret: TransferSec;
    ciphertext: string;
    memo: string;
    out_hashes: string[];
    commitment_root: string;
    parsed_delta: { v: string; e: string; index: string; };
}

export interface TreePub {
    root_before: string;
    root_after: string;
    leaf: string;
}

export interface TreeSec {
    proof_filled: MerkleProof;
    proof_free: MerkleProof;
    prev_leaf: string;
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
    a: [string, string];
    b: [[string, string], [string, string]];
    c: [string, string];
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Note[]")]
    pub type Notes;

    #[wasm_bindgen(typescript_type = "{ note: Note, index: number }[]")]
    pub type IndexedNotes;

    #[wasm_bindgen(typescript_type = "MerkleProof")]
    pub type MerkleProof;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type MerkleProofSibling;

    #[wasm_bindgen(typescript_type = "boolean[]")]
    pub type MerkleProofPath;

    #[wasm_bindgen(typescript_type = "Array<Output> | string")]
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

    #[wasm_bindgen(typescript_type = "TreePub")]
    pub type TreePub;

    #[wasm_bindgen(typescript_type = "TreeSec")]
    pub type TreeSec;

    #[wasm_bindgen(typescript_type = "Proof")]
    pub type Proof;

    #[wasm_bindgen(typescript_type = "SnarkProof")]
    pub type SnarkProof;

    #[wasm_bindgen(typescript_type = "TransactionData")]
    pub type TransactionData;

    #[wasm_bindgen(typescript_type = "Constants")]
    pub type Constants;

    #[wasm_bindgen(typescript_type = "string[]")]
    pub type Hashes;

    #[wasm_bindgen(typescript_type = "string")]
    pub type Hash;
}
