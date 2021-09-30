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
}

const Params = {
    fromBinary: zp.readParamsFromBinary,
    fromFile: zp.readParamsFromFile,
};
 
const Proof = {
    tx: zp.proveTx,
    tree: zp.proveTree,
};

class Helpers {
    static outCommitmentHash(outHashes) {
        return zp.helpersOutCommitment(outHashes)
    }

    static parseDelta(delta) {
        return zp.helpersParseDelta(delta)
    }
}

zp.MerkleTree = MerkleTree;
zp.TxStorage = TxStorage;
zp.Params = Params;
zp.Proof = Proof
zp.Helpers = Helpers;
module.exports = zp;
