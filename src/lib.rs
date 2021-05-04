use borsh::BorshSerialize;
use fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use js_sys::Function;
use libzeropool::native::cypher;
use libzeropool::native::params::PoolParams;
use libzeropool::{native::tx, POOL_PARAMS};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use web_sys::Performance;

mod merkle;
mod random;
mod utils;

pub struct Timer {
    start: f64,
    perf: Performance,
}

impl Timer {
    pub fn now() -> Timer {
        let perf = web_sys::window().unwrap().performance().unwrap();
        Timer {
            start: perf.now(),
            perf,
        }
    }

    pub fn elapsed_s(&self) -> f64 {
        (self.perf.now() - self.start) / 1000.0
    }
}

const ADDR_LEN: usize = 46;

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
    let mut buf: Vec<u8> = Vec::with_capacity(ADDR_LEN);

    buf.extend_from_slice(&d.to_uint().0.to_big_endian()[0..10]);
    buf.extend_from_slice(&pk_d.x.to_uint().0.to_big_endian()); // 32 bytes

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finalize();

    buf.extend_from_slice(&hash[0..4]);

    Ok(bs58::encode(buf).into_string())
}

pub fn parse_address(address: String) -> Result<(), JsValue> {
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(&address)
        .into(&mut bytes)
        .map_err(|err| JsValue::from(err.to_string()))?;

    let d = &bytes[0..10];
    let pk_d = &bytes[10..42];
    let parsed_hash = &bytes[42..46];

    let mut hasher = Sha256::new();
    hasher.update(&bytes[0..42]);
    let hash = hasher.finalize();

    if &hash[0..4] != parsed_hash {
        return Err(JsValue::from("Invalid address: incorrect hash"));
    }

    // let d = Num::from(d);
    // let pk_d = Num::from(pk_d);

    Ok(())
}

#[wasm_bindgen(js_name = decryptNote)]
pub fn decrypt_note(data: Vec<u8>) -> Option<String> {
    utils::set_panic_hook();

    let note = cypher::decrypt_in(receiver_dk, &data, &*POOL_PARAMS).or_else(|| {
        cypher::decrypt_out(sender_xsk, sender_adk, sender_sdk, &data, &*POOL_PARAMS)
            .map(|(_, note)| note)
    })?;

    let bytes = note.try_to_vec().unwrap();
    Some(base64::encode(bytes))
}

#[wasm_bindgen(js_name = "testMerkleTree")]
pub fn test_merkle_tree() {
    use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
    use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
    use fawkes_crypto::circuit::num::CNum;
    use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
    use fawkes_crypto::core::signal::Signal;
    use fawkes_crypto::core::sizedvec::SizedVec;
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

    let time = Timer::now();
    let params = setup::setup::<Bn256, _, _, _>(circuit);
}

#[wasm_bindgen(js_name = testPoseidonMerkleRoot)]
pub fn test_circuit_poseidon_merkle_root(callback: Function) {
    use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
    use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
    use fawkes_crypto::circuit::num::CNum;
    use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
    use fawkes_crypto::core::signal::Signal;
    use fawkes_crypto::core::sizedvec::SizedVec;
    use fawkes_crypto::engines::bn256::Fr;
    use fawkes_crypto::ff_uint::PrimeField;
    use fawkes_crypto::native::poseidon::{
        poseidon_merkle_proof_root, MerkleProof, PoseidonParams,
    };

    macro_rules! log_js {
        ($func:expr, $text:expr, $time:expr) => {{
            $func
                .call2(
                    &JsValue::NULL,
                    &JsValue::from($text),
                    &JsValue::from($time.elapsed_s()),
                )
                .unwrap();
        }};
    }

    fn circuit<Fr: PrimeField>(public: CNum<Fr>, secret: (CNum<Fr>, CMerkleProof<Fr, 32>)) {
        let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
        let res = c_poseidon_merkle_proof_root(&secret.0, &secret.1, &poseidon_params);
        res.assert_eq(&public);
    }

    utils::set_panic_hook();

    let time = Timer::now();
    let params = setup::setup::<Bn256, _, _, _>(circuit);
    log_js!(callback, "Setup", time);

    let time = Timer::now();
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
    log_js!(callback, "Merkle tree init", time);

    let time = Timer::now();
    let (inputs, snark_proof) = prover::prove(&params, &root, &(leaf, proof), circuit);
    log_js!(callback, "Prove", time);

    let time = Timer::now();
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    log_js!(callback, "Verify", time);

    assert!(res, "Verifier result should be true");
}
