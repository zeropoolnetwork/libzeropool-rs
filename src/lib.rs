use js_sys::Array;
use libzeropool::fawkes_crypto::borsh::BorshDeserialize;
use libzeropool::fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use libzeropool::native::cipher;
use libzeropool::native::key::{derive_key_a, derive_key_eta, derive_key_p_d};
use libzeropool::native::params::{PoolBN256, PoolParams};
use libzeropool::POOL_PARAMS;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub use crate::merkle::*;
use crate::state::{State, Transaction};
use crate::types::{Fr, Fs, Note, Notes, Pair, TransferPub, TransferSec};
use libzeropool::fawkes_crypto::native::poseidon::{poseidon, MerkleProof};
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::boundednum::BoundedNum;
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::tx::{
    make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub as NativeTransferPub,
    TransferSec as NativeTransferSec, Tx as NativeTx,
};
use std::str::FromStr;

mod merkle;
mod random;
mod sparse_array;
mod state;
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

pub fn parse_address<P: PoolParams>(address: &str) -> Result<(Num<P::Fr>, Num<P::Fr>), JsValue> {
    let mut bytes = [0; ADDR_LEN];
    bs58::decode(address)
        .into(&mut bytes)
        .map_err(|err| JsValue::from(err.to_string()))?;

    let d = &bytes[0..10];
    let p_d = &bytes[10..42];
    let parsed_hash = &bytes[42..46];

    let mut hasher = Sha256::new();
    hasher.update(&bytes[0..42]);
    let hash = hasher.finalize();

    if &hash[0..4] != parsed_hash {
        return Err(JsValue::from("Invalid address: incorrect hash"));
    }

    let d = Num::<P::Fr>::try_from_slice(d).unwrap();
    let p_d = Num::<P::Fr>::try_from_slice(p_d).unwrap();

    Ok((d, p_d))
}

pub fn derive_keys<P: PoolParams>(
    sk: &[u8],
    params: &P,
) -> Result<(Num<P::Fs>, Num<P::Fr>, Num<P::Fr>), JsValue> {
    let num_sk = Num::try_from_slice(&sk).map_err(|err| JsValue::from(err.to_string()))?;
    let a = derive_key_a(num_sk, params).x;
    let eta = derive_key_eta(a, params);

    Ok((num_sk, a, eta))
}

// TODO: Find a more appropriate name for this.
#[wasm_bindgen]
pub struct UserAccount {
    sk: Num<Fs>,
    a: Num<Fr>,
    eta: Num<Fr>,

    state: State,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(sk: Vec<u8>, state: State) -> Result<UserAccount, JsValue> {
        let (sk, a, eta) = derive_keys(&sk, &*POOL_PARAMS)?;

        Ok(UserAccount { sk, a, eta, state })
    }

    #[wasm_bindgen(js_name = fromSeed)]
    pub fn from_seed(seed: &[u8], state: State) -> Result<UserAccount, JsValue> {
        let sk = derive_sk(seed);
        Self::new(sk, state)
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

    // TODO: Error handling
    #[wasm_bindgen(js_name = makeTx)]
    pub fn make_tx(&mut self, to: &str, amount: &str) -> JsValue {
        let mut rng = random::CustomRng;

        let account_index = self.state.latest_usable_index();
        let memo = rng.gen(); // FIXME
        let prev_account: NativeAccount<Fr> =
            self.state.latest_account().unwrap_or_else(|| rng.gen());
        let next_usable_index = self.state.earliest_usable_index();
        let in_notes: Vec<(u32, NativeNote<Fr>)> = self
            .state
            .txs()
            .iter_slice(next_usable_index..=self.state.latest_note_index)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(note) => Some((index, note)),
                _ => None,
            })
            .collect();

        let amount = Num::from_str(amount).unwrap();

        let (_, to_p_d) = parse_address::<PoolBN256>(to).unwrap();

        let mut input_value = prev_account.b.to_num();
        for (_index, note) in &in_notes {
            input_value += note.b.to_num();
        }

        let mut input_energy = prev_account.e.to_num();
        input_energy +=
            prev_account.b.to_num() * (Num::from(account_index) - prev_account.i.to_num());

        for (note_index, note) in &in_notes {
            input_energy +=
                note.b.to_num() * Num::from((account_index - (2 * note_index + 1)) as u32);
        }

        let mut out_account: NativeAccount<Fr> = rng.gen();
        out_account.b = BoundedNum::new(input_value);
        out_account.e = BoundedNum::new(input_energy);
        out_account.i = BoundedNum::new(Num::from(account_index)); // index of lates note spent
        out_account.eta = self.eta;

        let out_account_hash = out_account.hash(&*POOL_PARAMS);
        let nullifier = nullifier(out_account_hash, self.eta, &*POOL_PARAMS);

        let mut out_note: NativeNote<Fr> = NativeNote::sample(&mut rng, &*POOL_PARAMS);
        out_note.p_d = to_p_d;
        out_note.b = BoundedNum::new(Num::from(amount));
        let out_note_hash = out_note.hash(&*POOL_PARAMS);

        let mut input_hashes = vec![prev_account.hash(&*POOL_PARAMS)];
        for (_index, note) in &in_notes {
            input_hashes.push(note.hash(&*POOL_PARAMS));
        }

        let output_hashes = vec![
            out_account.hash(&*POOL_PARAMS),
            out_note.hash(&*POOL_PARAMS),
        ];
        let out_ch = out_commitment_hash(&output_hashes, &*POOL_PARAMS);
        let tx_hash = tx_hash(&input_hashes, out_ch, &*POOL_PARAMS);
        let (eddsa_s, eddsa_r) = tx_sign(self.sk, tx_hash, &*POOL_PARAMS);

        let out_commit = poseidon(&output_hashes, &*POOL_PARAMS.compress());
        let delta = make_delta::<Fr>(
            input_value + amount,
            input_energy,
            Num::from(account_index as u32),
        );

        let mut tree = self.state.tree_mut();
        let new_account_index = tree.append_hash(out_account_hash, false);
        let _new_note_index = tree.append_hash(out_note_hash, false);
        let acc_proof = tree.get_proof(new_account_index).unwrap();

        // TODO: Is this correct
        let root: Num<Fr> = *acc_proof.sibling.as_slice().last().unwrap();

        let public = NativeTransferPub::<Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,
        };

        let tx = NativeTx {
            input: (
                prev_account.clone(),
                in_notes.iter().map(|(_, note)| note).cloned().collect(),
            ),
            output: (out_account, vec![out_note].into_iter().collect()),
        };

        let secret = NativeTransferSec::<Fr> {
            tx,
            in_proof: (
                self.merkle_proof(account_index),
                in_notes
                    .iter()
                    .map(|(index, _note)| self.merkle_proof(*index)) // FIXME: Calculate proof
                    .collect(),
            ),
            eddsa_s: eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a: self.a,
        };

        let data = TransactionData { public, secret };

        JsValue::from_serde(&data).unwrap()
    }

    fn merkle_proof(&self, index: u32) -> MerkleProof<Fr, { libzeropool::constants::HEIGHT }> {
        self.state.tree().get_proof(index).unwrap()
    }
}

#[wasm_bindgen]
#[derive(Serialize)]
pub struct TransactionData {
    public: NativeTransferPub<Fr>,
    secret: NativeTransferSec<Fr>,
}
