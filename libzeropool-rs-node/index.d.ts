export namespace Constants {
    export const HEIGHT: number;
    export const IN: number;
    export const OUTLOG: number;
    export const OUT: number;
}

declare class MerkleTree {
    constructor(path: string);

    getRoot(): string
    getNode(height: number, index: number): string;
    addHash(index: number, hash: Buffer): void;
    appendHash(hash: Buffer): number;
    getProof(index: number): MerkleProof;
    getCommitmentProof(index: number): MerkleProof;
}

declare class TxStorage {
    constructor(path: string);
    add(index: BigInt, data: Buffer): void;
    get(index: BigInt): Buffer | null;
    delete(index: BigInt): void;
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
    path: boolean[];
}

export interface SnarkProof {
    a: [string, string];
    b: [[string, string], [string, string]];
    c: [string, string];
}

declare class Params {
    static fromBinary(data: Buffer): Params;
    static fromFile(path: string): Params;
}

declare class Proof {
    inputs: Array<string>;
    proof: SnarkProof;

    static tx(params: Params, tr_pub: TransferPub, tr_sec: TransferSec): Proof;
    static tree(params: Params, tr_pub: TreePub, tr_sec: TreeSec): Proof;
}

declare class Helpers {
    static outCommitmentHash(hashes: Array<Buffer>): string
}
