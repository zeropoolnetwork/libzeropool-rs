use libzeropool::{
    constants,
    fawkes_crypto::{
        ff_uint::{Num, PrimeField},
        native::poseidon::MerkleProof,
    },
    native::{boundednum::BoundedNum, note::Note},
};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    use sha3::Digest;

    let mut hasher = sha3::Keccak256::new();
    hasher.update(data);
    let mut res = [0u8; 32];
    res.iter_mut()
        .zip(hasher.finalize().into_iter())
        .for_each(|(l, r)| *l = r);
    res
}

pub fn zero_note<Fr: PrimeField>() -> Note<Fr> {
    Note {
        d: BoundedNum::new(Num::ZERO),
        p_d: Num::ZERO,
        b: BoundedNum::new(Num::ZERO),
        t: BoundedNum::new(Num::ZERO),
    }
}

pub fn zero_proof<Fr: PrimeField>() -> MerkleProof<Fr, { constants::HEIGHT }> {
    MerkleProof {
        sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
        path: (0..constants::HEIGHT).map(|_| false).collect(),
    }
}
