const zp = require('./index.node');

class MerkleTree {
    constructor(path) {
        this.inner = zp.merkleNew(path);
    }

    getRoot() {
        return zp.merkleGetRoot(this.inner)
    }

    addHash(index, hash) {
        zp.merkleAddHash(this.inner, index, hash);
    }

    getProof(index) {
        return zp.merkleGetProof(this.inner, index);
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

zp.MerkleTree = MerkleTree;
zp.TxStorage = TxStorage;
zp.Params = Params;
zp.Proof = Proof
module.exports = zp;
