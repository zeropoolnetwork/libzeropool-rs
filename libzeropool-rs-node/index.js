const zp = require('./index.node');

class MerkleTree {
    constructor(path) {
        this.inner = zp.merkleNew(path);
    }

    getRoot() {
        return zp.merkleGetRoot(this.inner)
    }

    getNextIndex() {
        return zp.merkleGetNextIndex(this.inner)
    }

    getNode(height, index) {
        return zp.merkleGetNode(this.inner, height, index)
    }

    addHash(index, hash) {
        zp.merkleAddHash(this.inner, index, hash);
    }

    addCommitment(index, hash) {
        zp.merkleAddCommitment(this.inner, index, hash)
    }

    appendHash(hash) {
        return zp.merkleAppendHash(this.inner, hash);
    }

    getProof(index) {
        return zp.merkleGetProof(this.inner, index);
    }

    getCommitmentProof(index) {
        return zp.merkleGetCommitmentProof(this.inner, index)
    }

    getAllNodes() {
        return zp.merkleGetAllNodes(this.inner)
    }

    getVirtualNode(
        height,
        index,
        virtual_nodes,
        new_hashes_left_index,
        new_hashes_right_index,
    ) {
        return zp.merkleGetVirtualNode(
            this.inner,
            height,
            index,
            virtual_nodes,
            new_hashes_left_index,
            new_hashes_right_index,
        )
    }

    rollback(index) {
        return zp.merkleRollback(this.inner, index)
    }
}

class TxStorage {
    constructor(path) {
        this.inner = zp.txStorageNew(path);
    }

    add(index, data) {
        zp.txStorageAdd(this.inner, index, data);
    }

    get(index) {
        return zp.txStorageGet(this.inner, index);
    }

    delete(index) {
        return zp.txStorageDelete(this.inner, index);
    }

    count() {
        return zp.txStorageCount(this.inner);
    }
}

const Params = {
    fromBinary: zp.readParamsFromBinary,
    fromFile: zp.readParamsFromFile,
};

const Proof = {
    tx: zp.proveTx,
    tree: zp.proveTree,
    delegatedDeposit: zp.proveDelegatedDeposit,
    txAsync: zp.proveTxAsync,
    treeAsync: zp.proveTreeAsync,
    delegatedDepositAsync: zp.proveDelegatedDepositAsync,
    verify: zp.verify,
};

class Helpers {
    static outCommitmentHash(outHashes) {
        return zp.helpersOutCommitment(outHashes)
    }

    static parseDelta(delta) {
        return zp.helpersParseDelta(delta)
    }

    static numToStr(num) {
        return zp.helpersNumToStr(num)
    }

    static strToNum(str) {
        return zp.helpersStrToNum(str)
    }
}

class Keys {
    static derive(sk) {
        return zp.keysDerive(sk);
    }
}

class DelegatedDepositsData {
    static async create(
        deposits,
        ddParams,
    ) {
        return await zp.createDelegatedDepositTxAsync(
            deposits,
            ddParams,
        );
    }
}

zp.MerkleTree = MerkleTree;
zp.TxStorage = TxStorage;
zp.Params = Params;
zp.Proof = Proof
zp.Helpers = Helpers;
zp.Keys = Keys;
zp.DelegatedDepositsData = DelegatedDepositsData;
module.exports = zp;
