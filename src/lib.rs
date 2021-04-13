use fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use libzeropool::{native::tx, POOL_PARAMS};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

mod random;
mod utils;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = deriveAddress)]
pub fn derive_address(dk: &[u8]) -> Result<String, JsValue> {
    let mut rng = random::CustomRng;
    let d = rng.gen();
    let dk = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(dk)));
    let pk_d = tx::derive_key_pk_d(d, dk, &*POOL_PARAMS);
    let mut buf: Vec<u8> = Vec::with_capacity(48);

    buf.extend_from_slice(&d.to_uint().0.to_big_endian()[0..10]);
    buf.extend_from_slice(&pk_d.x.to_uint().0.to_big_endian()); // 32 bytes

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finalize();

    buf.extend_from_slice(&hash[0..4]);

    Ok(bs58::encode(buf).into_string())
}

#[wasm_bindgen(js_name = testPoseidonMerkleTree)]
pub fn test_circuit_poseidon_merkle_root() {
    use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
    use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
    use fawkes_crypto::circuit::num::CNum;
    use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
    use fawkes_crypto::core::signal::Signal;
    use fawkes_crypto::core::sizedvec::SizedVec;
    use fawkes_crypto::engines::bls12_381;
    use fawkes_crypto::engines::bn256::Fr;
    use fawkes_crypto::ff_uint::PrimeField;
    use fawkes_crypto::native::poseidon::{
        poseidon_merkle_proof_root, MerkleProof, PoseidonParams,
    };

    fn circuit<Fr: PrimeField>(public: CNum<Fr>, secret: (CNum<Fr>, CMerkleProof<Fr, 32>)) {
        let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
        let res = c_poseidon_merkle_proof_root(&secret.0, &secret.1, &poseidon_params);
        res.assert_eq(&public);
    }

    utils::set_panic_hook();

    let params = setup::setup::<Bn256, _, _, _>(circuit);

    const PROOF_LENGTH: usize = 32;
    let mut rng = random::CustomRng;
    let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
    let leaf = rng.gen();
    let sibling = (0..PROOF_LENGTH)
        .map(|_| rng.gen())
        .collect::<SizedVec<_, PROOF_LENGTH>>();
    let path = (0..PROOF_LENGTH)
        .map(|_| rng.gen())
        .collect::<SizedVec<bool, PROOF_LENGTH>>();
    let proof = MerkleProof { sibling, path };
    let root = poseidon_merkle_proof_root(leaf, &proof, &poseidon_params);

    // let (inputs, snark_proof) = prover::prove(&params, &root, &(leaf, proof), circuit);

    // let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    // assert!(res, "Verifier result should be true");
}
