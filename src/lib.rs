use std::str::FromStr;

use js_sys::Array;
use libzeropool::fawkes_crypto::borsh::BorshDeserialize;
use libzeropool::fawkes_crypto::native::poseidon::poseidon;
use libzeropool::fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use libzeropool::native::account::Account as NativeAccount;
use libzeropool::native::boundednum::BoundedNum;
use libzeropool::native::cipher;
use libzeropool::native::key::{derive_key_a, derive_key_eta, derive_key_p_d};
use libzeropool::native::note::Note as NativeNote;
use libzeropool::native::params::{PoolBN256, PoolParams};
use libzeropool::native::tx::{
    make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub as NativeTransferPub,
    TransferSec as NativeTransferSec, Tx as NativeTx,
};
use libzeropool::{constants, POOL_PARAMS};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

pub use crate::merkle::*;
use crate::state::{State, Transaction};
use crate::types::{Fr, Note, Notes, Pair, TxDestinations};
use crate::utils::Base64;

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

struct Keys<P: PoolParams> {
    sk: Num<P::Fs>,
    a: Num<P::Fr>,
    eta: Num<P::Fr>,
}

impl<P: PoolParams> Keys<P> {
    pub fn derive(sk: &[u8], params: &P) -> Result<Self, JsValue> {
        let num_sk = Num::try_from_slice(sk).map_err(|err| JsValue::from(err.to_string()))?;
        let a = derive_key_a(num_sk, params).x;
        let eta = derive_key_eta(a, params);

        Ok(Keys { sk: num_sk, a, eta })
    }
}

#[wasm_bindgen]
pub struct UserAccount {
    keys: Keys<PoolBN256>,
    state: State,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    pub fn new(sk: Vec<u8>, state: State) -> Result<UserAccount, JsValue> {
        let keys = Keys::derive(&sk, &*POOL_PARAMS)?;

        Ok(UserAccount { keys, state })
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
        let pk_d = derive_key_p_d(d, self.keys.eta, &*POOL_PARAMS);
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

        let notes = cipher::decrypt_in(self.keys.eta, &data, &*POOL_PARAMS)
            .into_iter()
            .flatten()
            .map(Note::from)
            .map(JsValue::from)
            .collect::<Array>()
            .unchecked_into::<Notes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = decryptPair)]
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        utils::set_panic_hook();

        let pair =
            cipher::decrypt_out(self.keys.eta, &data, &*POOL_PARAMS).map(|(account, notes)| {
                let notes = notes.into_iter().map(Note::from).collect();
                Pair::new(account.into(), notes)
            });

        Ok(pair)
    }

    // #[wasm_bindgen(js_name = encryptTx)]
    // pub fn encrypt_tx(&self, account: Account, notes: Notes) {
    //     todo!("Is this needed?");
    // }

    // TODO: Error handling
    #[wasm_bindgen(js_name = makeTx)]
    pub fn make_tx(&mut self, destinations: TxDestinations, mut data: Option<Vec<u8>>) -> JsValue {
        let mut rng = random::CustomRng;

        #[derive(Deserialize)]
        struct Destination {
            to: String,
            amount: String,
        }

        let destinations: Vec<Destination> = destinations.into_serde().unwrap();

        let spend_interval_index = self.state.latest_usable_index() + 1;
        let prev_account = self
            .state
            .latest_account()
            .unwrap_or_else(|| NativeAccount {
                eta: self.keys.eta,
                i: BoundedNum::new(Num::ZERO),
                b: BoundedNum::new(Num::ZERO),
                e: BoundedNum::new(Num::ZERO),
                t: rng.gen(),
            });

        let next_usable_index = self.state.earliest_usable_index();

        let in_notes: Vec<(u32, NativeNote<Fr>)> = self
            .state
            .txs()
            .iter_slice(next_usable_index..=self.state.latest_note_index)
            .take(constants::IN)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(note) => Some((index, note)),
                _ => None,
            })
            .collect();

        let mut input_value = prev_account.b.to_num();
        for (_index, note) in &in_notes {
            input_value += note.b.to_num();
        }

        let mut input_energy = prev_account.e.to_num();
        input_energy +=
            prev_account.b.to_num() * (Num::from(spend_interval_index) - prev_account.i.to_num());

        for (note_index, note) in &in_notes {
            input_energy +=
                note.b.to_num() * Num::from((spend_interval_index - (2 * note_index + 1)) as u32);
        }

        let mut new_balance = input_value;

        // TODO: Check number of out notes and fill in with empty or return error
        let out_notes: Vec<_> = destinations
            .into_iter()
            .map(|dest| {
                let amount = Num::from_str(&dest.amount).unwrap();
                let (to_d, to_p_d) = parse_address::<PoolBN256>(&dest.to).unwrap();

                new_balance -= amount;

                NativeNote {
                    d: BoundedNum::new(to_d),
                    p_d: to_p_d,
                    b: BoundedNum::new(amount),
                    t: rng.gen(),
                }
            })
            .collect();

        let out_account = NativeAccount {
            eta: self.keys.eta,
            i: BoundedNum::new(Num::from(spend_interval_index)),
            b: BoundedNum::new(new_balance),
            e: BoundedNum::new(input_energy),
            t: rng.gen(),
        };

        let out_account_hash = out_account.hash(&*POOL_PARAMS);
        let nullifier = nullifier(out_account_hash, self.keys.eta, &*POOL_PARAMS);

        let ciphertext = {
            let entropy: [u8; 32] = rng.gen();
            cipher::encrypt(
                &entropy,
                self.keys.eta,
                out_account,
                &out_notes,
                &*POOL_PARAMS,
            )
        };

        let mut input_hashes = vec![prev_account.hash(&*POOL_PARAMS)];
        for (_index, note) in &in_notes {
            input_hashes.push(note.hash(&*POOL_PARAMS));
        }

        let out_note_hashes: Vec<_> = out_notes.iter().map(|n| n.hash(&*POOL_PARAMS)).collect();
        let output_hashes: Vec<_> = [out_account_hash]
            .iter()
            .chain(out_note_hashes.iter())
            .copied()
            .collect();

        let out_ch = out_commitment_hash(&output_hashes, &*POOL_PARAMS);
        let tx_hash = tx_hash(&input_hashes, out_ch, &*POOL_PARAMS);
        let out_commit = poseidon(&output_hashes, &*POOL_PARAMS.compress());

        let delta = make_delta::<Fr>(
            input_value,
            input_energy,
            Num::from(spend_interval_index as u32),
        );

        let tree = self.state.tree();
        let root: Num<Fr> = tree.get_root();

        let mut memo_data = ciphertext.clone();
        if let Some(data) = &mut data {
            memo_data.append(data);
        }

        let memo = Num::try_from_slice(&utils::keccak256(&memo_data)).unwrap();

        let public = NativeTransferPub::<Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,
        };

        let tx = NativeTx {
            input: (
                prev_account,
                in_notes.iter().map(|(_, note)| note).cloned().collect(),
            ),
            output: (out_account, out_notes.iter().copied().collect()),
        };

        // TODO: Create an abstraction for signatures
        let (eddsa_s, eddsa_r) = tx_sign(self.keys.sk, tx_hash, &*POOL_PARAMS);

        let secret = NativeTransferSec::<Fr> {
            tx,
            in_proof: (
                tree.get_proof(spend_interval_index).unwrap(),
                in_notes
                    .iter()
                    .map(|(index, _note)| tree.get_proof(*index).unwrap())
                    .collect(),
            ),
            eddsa_s: eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a: self.keys.a,
        };

        let data = TransactionData {
            public,
            secret,
            ciphertext: Base64(ciphertext),
            memo: Base64(memo_data),
        };

        JsValue::from_serde(&data).unwrap()
    }
}

#[wasm_bindgen]
#[derive(Serialize)]
pub struct TransactionData {
    public: NativeTransferPub<Fr>,
    secret: NativeTransferSec<Fr>,
    ciphertext: Base64,
    memo: Base64,
}
