use borsh::BorshDeserialize;
use fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use js_sys::Function;
use libzeropool::native::cypher;
use libzeropool::native::params::{PoolBN256, PoolParams};
use libzeropool::native::tx::{derive_key_adk, derive_key_dk, derive_key_sdk, derive_key_xsk};
use libzeropool::{native::tx, POOL_PARAMS};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use web_sys::Performance;

pub use crate::merkle::*;
pub use crate::types::*;

mod merkle;
mod random;
mod types;
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

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = deriveSecretKey)]
pub fn derive_sk(seed: &[u8]) -> Vec<u8> {
    let sk = Num::<<PoolBN256 as PoolParams>::Fr>::from_uint_reduced(NumRepr(
        Uint::from_big_endian(seed),
    ));
    sk.to_uint().0.to_big_endian()
}

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

pub fn parse_address<P: PoolParams>(address: String) -> Result<(Num<P::Fr>, Num<P::Fr>), JsValue> {
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

    let d = Num::<P::Fr>::try_from_slice(d).unwrap();
    let pk_d = Num::<P::Fr>::try_from_slice(pk_d).unwrap();

    Ok((d, pk_d))
}

pub fn derive_keys<P: PoolParams>(
    sk: &[u8],
    params: &P,
) -> Result<(Num<P::Fr>, Num<P::Fs>, Num<P::Fs>, Num<P::Fs>), JsValue> {
    let num_sk = Num::try_from_slice(&sk).map_err(|err| JsValue::from(err.to_string()))?;

    let xsk = derive_key_xsk(num_sk, params).x;
    let sdk = derive_key_sdk(xsk, params);
    let adk = derive_key_adk(xsk, params);
    let dk = derive_key_dk(xsk, params);

    Ok((xsk, sdk, adk, dk)) // TODO: Return a structure
}

#[wasm_bindgen(js_name = decryptNote)]
pub fn decrypt_note(data: Vec<u8>, sk: &[u8]) -> Result<Option<Note>, JsValue> {
    utils::set_panic_hook();

    let (_, _, _, dk) = derive_keys(sk, &*POOL_PARAMS)?; // TODO: Only derive dk
    let note = cypher::decrypt_in(dk, &data, &*POOL_PARAMS).map(Into::into);

    Ok(note)
}

#[wasm_bindgen(js_name = decryptPair)]
pub fn decrypt_pair(data: Vec<u8>, sk: &[u8]) -> Result<Option<Pair>, JsValue> {
    utils::set_panic_hook();

    let (xsk, sdk, adk, _) = derive_keys(sk, &*POOL_PARAMS)?;

    let pair = cypher::decrypt_out(xsk, adk, sdk, &data, &*POOL_PARAMS)
        .map(|(account, note)| Pair::new(account.into(), note.into()));

    Ok(pair)
}

// pub fn make_deposit_tx(sk: &[u8], address: String) -> (TransferPub, TransferSec) {
//     let (_, pk_d) = parse_address(address)?;
//     let (xsk, sdk, adk, _) = derive_keys(&sk, &*POOL_PARAMS)?;
//
//     let mut account: NativeAccount<PoolBN256> = rng.gen();
//     let mut note: NativeNote<PoolBN256> = rng.gen();
//
//     let data = cypher::encrypt(
//         esk,
//         sdk,
//         adk,
//         (account.clone(), note.clone()),
//         &*POOL_PARAMS,
//     );
// }

// pub async fn test_merkle_tree() {
//     use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
//     use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
//     use fawkes_crypto::circuit::num::CNum;
//     use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
//     use fawkes_crypto::core::signal::Signal;
//     use fawkes_crypto::core::sizedvec::SizedVec;
//     use fawkes_crypto::engines::bn256::Fr;
//     use fawkes_crypto::ff_uint::PrimeField;
//     use fawkes_crypto::native::poseidon::{
//         poseidon_merkle_proof_root, MerkleProof, PoseidonParams,
//     };
//
//     utils::set_panic_hook();
//
//     const N_ITEMS: usize = 432;
//
//     let mut items: Vec<(Account<_>, Note<_>)> =
//         (0..N_ITEMS).map(|_| (rng.gen(), rng.gen())).collect();
//
//     let tree = MerkleTree::new(&*POOL_PARAMS).await;
//
//     tree.add_note();
// }

#[wasm_bindgen(js_name = testPoseidonMerkleRoot)]
pub async fn test_circuit_poseidon_merkle_root(callback: Function) {
    use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
    use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
    use fawkes_crypto::circuit::num::CNum;
    use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
    use fawkes_crypto::core::signal::Signal;
    use fawkes_crypto::engines::bn256::Fr;
    use fawkes_crypto::ff_uint::PrimeField;
    use fawkes_crypto::native::poseidon::{poseidon_merkle_proof_root, PoseidonParams};

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
    let mut rng = random::CustomRng;
    let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
    let mut tree = MerkleTree::new_web(&*POOL_PARAMS).await;
    let leaf = rng.gen();
    tree.add_hash(0, leaf, false);

    let proof = tree.get_proof(0).unwrap();
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
