use fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use js_sys::Array;
use libzeropool::fawkes_crypto::borsh::BorshDeserialize;
use libzeropool::native::cipher;
use libzeropool::native::key::{derive_key_a, derive_key_eta, derive_key_p_d};
use libzeropool::native::params::{PoolBN256, PoolParams};
use libzeropool::POOL_PARAMS;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub use crate::merkle::*;
pub use crate::types::*;

mod merkle;
mod random;
mod types;
mod utils;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

const ADDR_LEN: usize = 46;

#[wasm_bindgen(js_name = deriveSecretKey)]
pub fn derive_sk(seed: &[u8]) -> Vec<u8> {
    let sk = Num::<<PoolBN256 as PoolParams>::Fr>::from_uint_reduced(NumRepr(
        Uint::from_big_endian(seed),
    ));
    sk.to_uint().0.to_big_endian()
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
) -> Result<(Num<P::Fr>, Num<P::Fr>), JsValue> {
    let num_sk = Num::try_from_slice(&sk).map_err(|err| JsValue::from(err.to_string()))?;
    let a = derive_key_a(num_sk, params).x;
    let eta = derive_key_eta(a, params);

    Ok((a, eta))
}

#[wasm_bindgen]
pub struct Account {
    eta: Num<Fr>,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen(constructor)]
    pub fn new(sk: Vec<u8>) -> Result<Account, JsValue> {
        let (_a, eta) = derive_keys(&sk, &*POOL_PARAMS)?;

        Ok(Account { eta })
    }

    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8]) -> Result<Account, JsValue> {
        let sk = derive_sk(seed);
        Self::new(sk)
    }

    #[wasm_bindgen(js_name = deriveNewAddress)]
    pub fn derive_new_address(&self) -> Result<String, JsValue> {
        let mut rng = random::CustomRng;

        let d = rng.gen();
        let pk_d = derive_key_p_d(d, self.eta, &*POOL_PARAMS);
        let mut buf: Vec<u8> = Vec::with_capacity(ADDR_LEN);

        buf.extend_from_slice(&d.to_uint().0.to_big_endian()[0..10]);
        buf.extend_from_slice(&pk_d.x.to_uint().0.to_big_endian()); // 32 bytes

        let mut hasher = Sha256::new();
        hasher.update(&buf);
        let hash = hasher.finalize();

        buf.extend_from_slice(&hash[0..4]);

        Ok(bs58::encode(buf).into_string())
    }

    #[wasm_bindgen(js_name = decryptNotes)]
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Result<Notes, JsValue> {
        utils::set_panic_hook();

        let notes = cipher::decrypt_in(self.eta, &data, &*POOL_PARAMS)
            .into_iter()
            .filter_map(|opt| opt)
            .map(Note::from)
            .map(JsValue::from)
            .collect::<Array>()
            .unchecked_into::<Notes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = decryptPair)]
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        utils::set_panic_hook();

        let pair = cipher::decrypt_out(self.eta, &data, &*POOL_PARAMS).map(|(account, notes)| {
            let notes = notes.into_iter().map(Note::from).collect();
            Pair::new(account.into(), notes)
        });

        Ok(pair)
    }
    //
    // #[wasm_bindgen(js_name = makeTransferTx)]
    // pub fn make_transfer_tx(&self) -> (TransferPub<PoolBN256>, TransferSec<PoolBN256>) {
    //     let root = self.root();
    //     let index = N_ITEMS * 2;
    //     let xsk = derive_key_xsk(self.sk, params).x;
    //     let nullifier = nullifier(self.hashes[0][self.account_id * 2], xsk, params);
    //     let memo = rng.gen();
    //
    //     let mut input_value = self.items[self.account_id].0.v.to_num();
    //     for &i in self.note_id.iter() {
    //         input_value += self.items[i].1.v.to_num();
    //     }
    //
    //     let mut input_energy = self.items[self.account_id].0.e.to_num();
    //     input_energy += self.items[self.account_id].0.v.to_num()
    //         * (Num::from(index as u32) - self.items[self.account_id].0.interval.to_num());
    //
    //     for &i in self.note_id.iter() {
    //         input_energy += self.items[i].1.v.to_num() * Num::from((index - (2 * i + 1)) as u32);
    //     }
    //
    //     let mut out_account: NativeAccount<P> = rng.gen();
    //     out_account.v = BoundedNum::new(input_value);
    //     out_account.e = BoundedNum::new(input_energy);
    //     out_account.interval = BoundedNum::new(Num::from(index as u32));
    //     out_account.xsk = xsk;
    //
    //     let mut out_note: Note<P> = rng.gen();
    //     out_note.v = BoundedNum::new(Num::ZERO);
    //
    //     let mut input_hashes = vec![self.items[self.account_id].0.hash(params)];
    //     for &i in self.note_id.iter() {
    //         input_hashes.push(self.items[i].1.hash(params));
    //     }
    //
    //     let output_hashes = vec![out_account.hash(params), out_note.hash(params)];
    //     let tx_hash = tx_hash(&input_hashes, &output_hashes, params);
    //     let (eddsa_s, eddsa_r) = tx_sign(self.sk, tx_hash, params);
    //
    //     let out_commit = poseidon(&output_hashes, params.compress());
    //     let delta = make_delta::<P>(Num::ZERO, Num::ZERO, Num::from(index as u32));
    //
    //     let p = TransferPub::<P> {
    //         root,
    //         nullifier,
    //         out_commit,
    //         delta,
    //         memo,
    //     };
    //
    //     let tx = Tx {
    //         input: (
    //             self.items[self.account_id].0.clone(),
    //             self.note_id
    //                 .iter()
    //                 .map(|&i| self.items[i].1.clone())
    //                 .collect(),
    //         ),
    //         output: (out_account, out_note),
    //     };
    //
    //     let s = TransferSec::<P> {
    //         tx,
    //         in_proof: (
    //             self.merkle_proof(self.account_id * 2),
    //             self.note_id
    //                 .iter()
    //                 .map(|&i| self.merkle_proof(i * 2 + 1))
    //                 .collect(),
    //         ),
    //         eddsa_s: eddsa_s.to_other().unwrap(),
    //         eddsa_r,
    //         eddsa_a: xsk,
    //     };
    //
    //     (p, s)
    // }
}
//
// #[wasm_bindgen(js_name = testPoseidonMerkleRoot)]
// pub async fn test_circuit_poseidon_merkle_root(callback: Function) {
//     use fawkes_crypto::backend::bellman_groth16::engines::Bn256;
//     use fawkes_crypto::backend::bellman_groth16::{prover, setup, verifier};
//     use fawkes_crypto::circuit::num::CNum;
//     use fawkes_crypto::circuit::poseidon::{c_poseidon_merkle_proof_root, CMerkleProof};
//     use fawkes_crypto::core::signal::Signal;
//     use fawkes_crypto::engines::bn256::Fr;
//     use fawkes_crypto::ff_uint::PrimeField;
//     use fawkes_crypto::native::poseidon::{poseidon_merkle_proof_root, PoseidonParams};
//     use web_sys::Performance;
//
//     use self::utils::Timer;
//
//     macro_rules! log_js {
//         ($func:expr, $text:expr, $time:expr) => {{
//             $func
//                 .call2(
//                     &JsValue::NULL,
//                     &JsValue::from($text),
//                     &JsValue::from($time.elapsed_s()),
//                 )
//                 .unwrap();
//         }};
//     }
//
//     fn circuit<Fr: PrimeField>(public: CNum<Fr>, secret: (CNum<Fr>, CMerkleProof<Fr, 32>)) {
//         let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
//         let res = c_poseidon_merkle_proof_root(&secret.0, &secret.1, &poseidon_params);
//         res.assert_eq(&public);
//     }
//
//     utils::set_panic_hook();
//
//     let time = Timer::now();
//     let params = setup::setup::<Bn256, _, _, _>(circuit);
//     log_js!(callback, "Setup", time);
//
//     let time = Timer::now();
//     let mut rng = random::CustomRng;
//     let poseidon_params = PoseidonParams::<Fr>::new(3, 8, 53);
//     let mut tree = MerkleTree::new_web(&*POOL_PARAMS).await;
//     let leaf = rng.gen();
//     tree.add_hash(0, leaf, false);
//
//     let proof = tree.get_proof(0).unwrap();
//     let root = poseidon_merkle_proof_root(leaf, &proof, &poseidon_params);
//     log_js!(callback, "Merkle tree init", time);
//
//     let time = Timer::now();
//     let (inputs, snark_proof) = prover::prove(&params, &root, &(leaf, proof), circuit);
//     log_js!(callback, "Prove", time);
//
//     let time = Timer::now();
//     let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
//     log_js!(callback, "Verify", time);
//
//     assert!(res, "Verifier result should be true");
// }
