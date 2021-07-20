use js_sys::Array;
use libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec, ff_uint::Num, native::poseidon::poseidon,
        native::poseidon::MerkleProof, rand::Rng,
    },
    native::{
        account::Account as NativeAccount,
        boundednum::BoundedNum,
        cipher,
        key::derive_key_p_d,
        note::Note as NativeNote,
        params::{PoolBN256, PoolParams},
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign,
            TransferPub as NativeTransferPub, TransferSec as NativeTransferSec, Tx as NativeTx,
        },
    },
    POOL_PARAMS,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};

pub use crate::{
    address::{format_address, parse_address},
    keys::{derive_sk, Keys},
    merkle::*,
    state::{State, Transaction},
};
use crate::{
    types::{Fr, Note, Notes, Pair, TxOutputs},
    utils::Base64,
};
use libzeropool::fawkes_crypto::ff_uint::{NumRepr, Uint};

mod address;
mod keys;
mod merkle;
mod random;
mod sparse_array;
mod state;
mod types;
mod utils;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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

    #[wasm_bindgen(js_name = generateAddress)]
    pub fn generate_address(&self) -> String {
        let mut rng = random::CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), self.keys.eta, &*POOL_PARAMS);
        format_address::<PoolBN256>(d, pk_d.x)
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
    pub fn make_tx(&self, outputs: TxOutputs, mut data: Option<Vec<u8>>) -> JsValue {
        utils::set_panic_hook();

        let mut rng = random::CustomRng;

        #[derive(Deserialize)]
        struct Output {
            to: String,
            amount: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
        }

        fn null_note() -> NativeNote<Fr> {
            NativeNote {
                d: BoundedNum::new(Num::ZERO),
                p_d: Num::ZERO,
                b: BoundedNum::new(Num::ZERO),
                t: BoundedNum::new(Num::ZERO),
            }
        }

        fn null_proof() -> MerkleProof<Fr, { constants::HEIGHT }> {
            MerkleProof {
                sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
                path: (0..constants::HEIGHT).map(|_| false).collect(),
            }
        }

        let outputs: Vec<Output> = outputs.into_serde().unwrap();

        assert!(outputs.len() <= constants::IN, "Too many outputs"); // TODO: Return an error

        let spend_interval_index = self.state.latest_note_index + 1;
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

        let in_notes: Vec<(u64, NativeNote<Fr>)> = self
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
            input_energy += note.b.to_num() * Num::from(spend_interval_index - note_index);
        }

        let mut output_value = Num::ZERO;
        let out_notes: SizedVec<_, { constants::OUT }> = outputs
            .iter()
            .map(|dest| {
                let (to_d, to_p_d) = parse_address::<PoolBN256>(&dest.to).unwrap();

                output_value += dest.amount.to_num();

                NativeNote {
                    d: to_d,
                    p_d: to_p_d,
                    b: dest.amount,
                    t: rng.gen(),
                }
            })
            // fill out remaining output notes with zeroes
            .chain((outputs.len()..constants::OUT).map(|_| null_note()))
            .collect();

        let new_balance = input_value - output_value;

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
                out_notes.as_slice(),
                &*POOL_PARAMS,
            )
        };

        let mut input_hashes = vec![prev_account.hash(&*POOL_PARAMS)];
        for (_index, note) in &in_notes {
            input_hashes.push(note.hash(&*POOL_PARAMS));
        }

        if in_notes.len() < constants::IN {
            for _ in in_notes.len()..=constants::IN {
                input_hashes.push(Num::ZERO);
            }
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

        let memo_hash = utils::keccak256(&memo_data);
        let memo = Num::from_uint_reduced(NumRepr(Uint::from_little_endian(&memo_hash)));

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
                in_notes
                    .iter()
                    .map(|(_, note)| note)
                    .cloned()
                    .chain((in_notes.len()..constants::IN).map(|_| null_note()))
                    .collect(),
            ),
            output: (out_account, out_notes),
        };

        // TODO: Create an abstraction for signatures
        let (eddsa_s, eddsa_r) = tx_sign(self.keys.sk, tx_hash, &*POOL_PARAMS);

        let zero_note_proofs = (in_notes.len()..constants::IN).map(|_| null_proof());

        let note_proofs = in_notes
            .iter()
            .copied()
            .map(|(index, _note)| tree.get_proof(index).unwrap())
            .chain(zero_note_proofs)
            .collect();

        let secret = NativeTransferSec::<Fr> {
            tx,
            in_proof: (
                tree.get_proof(self.state.latest_account_index)
                    .unwrap_or(null_proof()), // FIXME: Which proof to use here?
                note_proofs,
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
