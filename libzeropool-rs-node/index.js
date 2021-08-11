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

zp.MerkleTree = MerkleTree;
module.exports = zp;