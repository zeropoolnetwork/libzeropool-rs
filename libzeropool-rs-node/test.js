const zp = require('./index.js')

let tree = new zp.MerkleTree('./testdb');

for (let i = 0; i < 100; ++i) {
    tree.addHash(i, Buffer.alloc(32));
}

let proof = tree.getProof(50);
console.log('Proof', proof);