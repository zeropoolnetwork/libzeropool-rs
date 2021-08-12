declare class MerkleTree {
    constructor(path: string);

    addHash(index: BigInt, hash: Buffer): void;
    getProof(index: BigInt): MerkleProof;
}

declare class TxStorage {
    constructor(path: string);
    add(index: BigInt, data: Buffer): void;
    get(index: BigInt): ?Buffer;
    delete(index: BigInt);
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

export interface MerkleProof {
    sibling: string[];
    path: boolena[];
}

export interface SnarkProof {
    inputs: Array<string>;
    proof: SnarkProof;
}

declare class Params {
    static fromBinary(data: Buffer): Params;
    static fromFile(path: string): Params;
}

declare function proveTx(params: Params, tr_pub: TransferPub, tr_sec: TransferSec): SnarkProof;
declare function proveTree(params: Params, tr_pub: TreePub, tr_sec: TreeSec): SnarkProof;


