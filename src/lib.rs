use std::{cell::RefCell, rc::Rc};

use js_sys::{Array, Promise};
use libzeropool::{
    constants,
    fawkes_crypto::{
        backend::bellman_groth16::engines::Bn256,
        core::sizedvec::SizedVec,
        ff_uint::Num,
        ff_uint::{NumRepr, Uint},
        native::poseidon::poseidon,
        native::poseidon::MerkleProof,
        rand::Rng,
    },
    native::{
        account::Account as NativeAccount,
        boundednum::BoundedNum,
        cipher,
        key::derive_key_p_d,
        note::Note as NativeNote,
        params::{PoolBN256, PoolParams as PoolParamsTrait},
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign,
            TransferPub as NativeTransferPub, TransferSec as NativeTransferSec, Tx as NativeTx,
        },
    },
    POOL_PARAMS,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};

use crate::{
    address::AddressParseError,
    ts_types::{Account, Note, Notes, Pair, TxOutputs},
    utils::Base64,
};
pub use crate::{
    address::{format_address, parse_address},
    keys::{derive_sk, Keys},
    merkle::*,
    params::*,
    proof::*,
    state::{State, Transaction},
};
use wasm_bindgen_futures::future_to_promise;

#[macro_use]
mod utils;
mod address;
mod keys;
mod merkle;
mod params;
mod proof;
mod random;
mod sparse_array;
mod state;
mod ts_types;

#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

// TODO: Implement a native interface first, then create wasm bindings.

#[wasm_bindgen]
pub struct UserAccount {
    keys: Keys,
    state: Rc<RefCell<State>>,
}

#[wasm_bindgen]
impl UserAccount {
    #[wasm_bindgen(constructor)]
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: Vec<u8>, state: State) -> Result<UserAccount, JsValue> {
        let keys = Keys::derive(&sk)?;

        Ok(UserAccount {
            keys,
            state: Rc::new(RefCell::new(state)),
        })
    }

    // TODO: Is this safe?
    #[wasm_bindgen(js_name = fromSeed)]
    /// Same as constructor but accepts arbitrary data as spending key.
    pub fn from_seed(seed: &[u8], state: State) -> Result<UserAccount, JsValue> {
        utils::set_panic_hook();

        let sk = derive_sk(seed);
        Self::new(sk, state)
    }

    #[wasm_bindgen(js_name = generateAddress)]
    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        utils::set_panic_hook();

        let mut rng = random::CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), self.keys.eta, &*POOL_PARAMS);
        format_address::<PoolBN256>(d, pk_d.x)
    }

    #[wasm_bindgen(js_name = decryptNotes)]
    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Result<Notes, JsValue> {
        utils::set_panic_hook();

        let notes = cipher::decrypt_in(self.keys.eta, &data, &*POOL_PARAMS)
            .into_iter()
            .flatten()
            .map(|note| serde_wasm_bindgen::to_value(&note).unwrap())
            .collect::<Array>()
            .unchecked_into::<Notes>();

        Ok(notes)
    }

    #[wasm_bindgen(js_name = decryptPair)]
    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Result<Option<Pair>, JsValue> {
        utils::set_panic_hook();

        #[derive(Serialize)]
        struct SerPair {
            account: NativeAccount<Fr>,
            notes: Vec<NativeNote<Fr>>,
        }

        let pair =
            cipher::decrypt_out(self.keys.eta, &data, &*POOL_PARAMS).map(|(account, notes)| {
                let pair = SerPair { account, notes };

                serde_wasm_bindgen::to_value(&pair)
                    .unwrap()
                    .unchecked_into::<Pair>()
            });

        Ok(pair)
    }

    #[wasm_bindgen(js_name = createTx, typescript_type = "Promise<TransactionData>")]
    /// Constructs a transaction.
    pub fn create_tx(&self, outputs: TxOutputs, mut data: Option<Vec<u8>>) -> Promise {
        utils::set_panic_hook();

        #[derive(Deserialize)]
        struct Output {
            to: String,
            amount: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
        }

        #[derive(Serialize)]
        pub struct TransactionData {
            public: NativeTransferPub<Fr>,
            secret: NativeTransferSec<Fr>,
            ciphertext: Base64,
            memo: Base64,
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

        let mut rng = random::CustomRng;
        let state = self.state.clone();
        let keys = self.keys.clone();

        future_to_promise(async move {
            let state = state.borrow();
            let outputs: Vec<Output> = serde_wasm_bindgen::from_value(outputs.into())?;

            if outputs.len() >= constants::IN {
                return Err(js_err!("Too many outputs (max: {})", constants::IN));
            }

            let spend_interval_index = state.latest_note_index + 1;
            let prev_account = state.latest_account.unwrap_or_else(|| NativeAccount {
                eta: Num::ZERO,
                i: BoundedNum::new(Num::ZERO),
                b: BoundedNum::new(Num::ZERO),
                e: BoundedNum::new(Num::ZERO),
                t: BoundedNum::new(Num::ZERO),
            });

            let next_usable_index = state.earliest_usable_index();

            // Fetch constants::IN usable notes from state
            let in_notes: Vec<(u64, NativeNote<Fr>)> = state
                .txs
                .iter_slice(next_usable_index..=state.latest_note_index)
                .take(constants::IN)
                .filter_map(|(index, tx)| match tx {
                    Transaction::Note(note) => Some((index, note)),
                    _ => None,
                })
                .collect();

            // Calculate total balance (account + constants::IN notes).
            let mut input_value = prev_account.b.to_num();
            for (_index, note) in &in_notes {
                input_value += note.b.to_num();
            }

            let mut input_energy = prev_account.e.to_num();
            input_energy += prev_account.b.to_num()
                * (Num::from(spend_interval_index) - prev_account.i.to_num());

            for (note_index, note) in &in_notes {
                input_energy += note.b.to_num() * Num::from(spend_interval_index - note_index);
            }

            let mut output_value = Num::ZERO;
            let out_notes: SizedVec<_, { constants::OUT }> = outputs
                .iter()
                .map(|dest| {
                    let (to_d, to_p_d) = parse_address::<PoolBN256>(&dest.to)?;

                    output_value += dest.amount.to_num();

                    Ok(NativeNote {
                        d: to_d,
                        p_d: to_p_d,
                        b: dest.amount,
                        t: rng.gen(),
                    })
                })
                // fill out remaining output notes with zeroes
                .chain((0..).map(|_| Ok(null_note())))
                .take(constants::OUT)
                .collect::<Result<SizedVec<_, { constants::OUT }>, AddressParseError>>()?;

            let new_balance = input_value - output_value;

            let out_account = NativeAccount {
                eta: keys.eta,
                i: BoundedNum::new(Num::from(spend_interval_index)),
                b: BoundedNum::new(new_balance),
                e: BoundedNum::new(input_energy),
                t: rng.gen(),
            };

            let out_account_hash = out_account.hash(&*POOL_PARAMS);
            let nullifier = nullifier(out_account_hash, keys.eta, &*POOL_PARAMS);

            let ciphertext = {
                let entropy: [u8; 32] = rng.gen();
                cipher::encrypt(
                    &entropy,
                    keys.eta,
                    out_account,
                    out_notes.as_slice(),
                    &*POOL_PARAMS,
                )
            };

            // Hash input account + notes filling remaining space with non-hashed zeroes
            let in_note_hashes = in_notes.iter().map(|(_, note)| note.hash(&*POOL_PARAMS));
            let input_hashes: SizedVec<_, { constants::IN }> = [prev_account.hash(&*POOL_PARAMS)]
                .iter()
                .copied()
                .chain(in_note_hashes)
                .chain((0..).map(|_| Num::ZERO))
                .take(constants::IN)
                .collect();

            // Same with output
            let out_note_hashes = out_notes.iter().map(|n| n.hash(&*POOL_PARAMS));
            let output_hashes: SizedVec<_, { constants::OUT + 1 }> = [out_account_hash]
                .iter()
                .copied()
                .chain(out_note_hashes)
                .chain((0..).map(|_| Num::ZERO))
                .take(constants::OUT + 1)
                .collect();

            let out_ch = out_commitment_hash(output_hashes.as_slice(), &*POOL_PARAMS);
            let tx_hash = tx_hash(input_hashes.as_slice(), out_ch, &*POOL_PARAMS);
            let out_commit = poseidon(output_hashes.as_slice(), &*POOL_PARAMS.compress());

            let delta = make_delta::<Fr>(
                input_value,
                input_energy,
                Num::from(spend_interval_index as u32),
            );

            let tree = &state.tree;
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
                        .chain((0..).map(|_| null_note()))
                        .take(constants::IN - 1)
                        .collect(),
                ),
                output: (out_account, out_notes),
            };
            // TODO: Create an abstraction for signatures
            let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, &*POOL_PARAMS);

            let note_proofs = in_notes
                .iter()
                .copied()
                .map(|(index, _note)| {
                    tree.get_proof(index)
                        .ok_or_else(|| js_err!("Could not get proof for leaf {}", index))
                })
                .chain((0..).map(|_| Ok(null_proof())))
                .take(constants::IN - 1)
                .collect::<Result<_, JsValue>>()?;

            let secret = NativeTransferSec::<Fr> {
                tx,
                in_proof: (
                    tree.get_proof(state.latest_account_index)
                        .unwrap_or_else(null_proof), // FIXME: Which proof to use here?
                    note_proofs,
                ),
                eddsa_s: eddsa_s.to_other().unwrap(),
                eddsa_r,
                eddsa_a: keys.a,
            };

            let data = TransactionData {
                public,
                secret,
                ciphertext: Base64(ciphertext),
                memo: Base64(memo_data),
            };

            Ok(serde_wasm_bindgen::to_value(&data).unwrap())
        })
    }

    #[wasm_bindgen(js_name = "addAccount")]
    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account) -> Result<(), JsValue> {
        self.state.borrow_mut().add_account(at_index, account)
    }

    #[wasm_bindgen(js_name = "addReceivedNote")]
    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note) -> Result<(), JsValue> {
        self.state.borrow_mut().add_received_note(at_index, note)
    }

    #[wasm_bindgen(js_name = "totalBalance")]
    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> String {
        self.state.borrow().total_balance()
    }
    //
    // #[wasm_bindgen(js_name = "takeState")]
    // /// Consumes the UserAccount and returns it's State.
    // pub fn take_state(self) -> State {
    //     self.state.take()
    // }
}
