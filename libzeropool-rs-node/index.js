const zp = require('./index.node');

class MerkleTree {
    constructor(path) {
        this.inner = zp.merkleNew(path);
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
    fromBinary(data) {
        zp.readParamsFromBinary(data);
    }
};

zp.MerkleTree = MerkleTree;
zp.TxStorage = TxStorage;
zp.Params = Params;
module.exports = zp;
