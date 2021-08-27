use kvdb::KeyValueDB;
use libzeropool::{
    constants,
    fawkes_crypto::ff_uint::PrimeField,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::Num,
        ff_uint::{NumRepr, Uint},
        native::poseidon::MerkleProof,
        rand::Rng,
    },
    native::{
        account::Account,
        boundednum::BoundedNum,
        cipher,
        key::derive_key_p_d,
        note::Note,
        params::PoolParams,
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub, TransferSec,
            Tx,
        },
    },
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use self::state::{State, Transaction};
use crate::{
    address::{format_address, parse_address, AddressParseError},
    keys::{reduce_sk, Keys},
    random::CustomRng,
    utils::keccak256,
};

pub mod state;

#[derive(Debug, Error)]
pub enum CreateTxError {
    #[error("Too many outputs: expected {max} max got {got}")]
    TooManyOutputs { max: usize, got: usize },
    #[error("Could not get merkle proof for leaf {0}")]
    ProofNotFound(u64),
    #[error("Failed to parse address: {0}")]
    AddressParseError(#[from] AddressParseError),
    #[error("Insufficient balance: sum of outputs is greater than sum of inputs")]
    InsufficientBalance,
}

#[derive(Serialize, Deserialize)]
pub struct TransactionData<Fr: PrimeField> {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub ciphertext: Vec<u8>,
    pub memo: Vec<u8>,
    pub out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
    pub output_energy: Num<Fr>,
    pub output_value: Num<Fr>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxOutput<Fr: PrimeField> {
    pub to: String,
    pub amount: BoundedNum<Fr, { constants::BALANCE_SIZE }>,
}

pub struct UserAccount<D: KeyValueDB, P: PoolParams> {
    pub keys: Keys<P>,
    pub params: P,
    pub state: State<D, P>,
    pub sign_callback: Option<Box<dyn Fn(&[u8]) -> Vec<u8>>>, // TODO: Find a way to make it async
}

impl<'p, D, P> UserAccount<D, P>
where
    D: KeyValueDB,
    P: PoolParams,
    P::Fr: 'static,
{
    /// Initializes UserAccount with a spending key that has to be an element of the prime field Fs (p = 6554484396890773809930967563523245729705921265872317281365359162392183254199).
    pub fn new(sk: Num<P::Fs>, state: State<D, P>, params: P) -> Self {
        let keys = Keys::derive(sk, &params);

        UserAccount {
            keys,
            state,
            params,
            sign_callback: None,
        }
    }

    /// Same as constructor but accepts arbitrary data as spending key.
    pub fn from_seed(seed: &[u8], state: State<D, P>, params: P) -> Self {
        let sk = reduce_sk(seed);
        Self::new(sk, state, params)
    }

    // TODO: Create a separate structure containing address elements
    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        let mut rng = CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), self.keys.eta, &self.params);
        format_address::<P>(d, pk_d.x)
    }

    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Vec<Option<Note<P::Fr>>> {
        cipher::decrypt_in(self.keys.eta, &data, &self.params)
    }

    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
        cipher::decrypt_out(self.keys.eta, &data, &self.params)
    }

    /// Constructs a transaction.
    pub fn create_tx(
        &self,
        outputs: &[TxOutput<P::Fr>],
        mut data: Option<Vec<u8>>,
    ) -> Result<TransactionData<P::Fr>, CreateTxError> {
        fn zero_note<Fr: PrimeField>() -> Note<Fr> {
            Note {
                d: BoundedNum::new(Num::ZERO),
                p_d: Num::ZERO,
                b: BoundedNum::new(Num::ZERO),
                t: BoundedNum::new(Num::ZERO),
            }
        }

        fn zero_proof<Fr: PrimeField>() -> MerkleProof<Fr, { constants::HEIGHT }> {
            MerkleProof {
                sibling: (0..constants::HEIGHT).map(|_| Num::ZERO).collect(),
                path: (0..constants::HEIGHT).map(|_| false).collect(),
            }
        }

        if outputs.len() >= constants::IN {
            return Err(CreateTxError::TooManyOutputs {
                max: constants::IN,
                got: outputs.len(),
            });
        }

        let mut rng = CustomRng;
        let keys = self.keys.clone();
        let state = &self.state;

        let next_index = state.tree.next_index();
        // FIXME: What if there are more owned notes than input limit? Only take as much as needed.
        let spend_interval_index = state.latest_note_index + 1;
        let prev_account = state.latest_account.unwrap_or_else(|| Account {
            eta: Num::ZERO,
            i: BoundedNum::new(Num::ZERO),
            b: BoundedNum::new(Num::ZERO),
            e: BoundedNum::new(Num::ZERO),
            t: BoundedNum::new(Num::ZERO),
        });

        let next_usable_index = state.earliest_usable_index();

        // Fetch constants::IN usable notes from state
        let in_notes: Vec<(u64, Note<P::Fr>)> = state
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
        input_energy +=
            prev_account.b.to_num() * (Num::from(spend_interval_index) - prev_account.i.to_num());

        for (note_index, note) in &in_notes {
            input_energy += note.b.to_num() * Num::from(spend_interval_index - note_index);
        }

        let mut output_value = Num::ZERO;
        let out_notes: SizedVec<_, { constants::OUT }> = outputs
            .iter()
            .map(|dest| {
                let (to_d, to_p_d) = parse_address::<P>(&dest.to)?;

                output_value += dest.amount.to_num();

                Ok(Note {
                    d: to_d,
                    p_d: to_p_d,
                    b: dest.amount,
                    t: rng.gen(),
                })
            })
            // fill out remaining output notes with zeroes
            .chain((0..).map(|_| Ok(zero_note())))
            .take(constants::OUT)
            .collect::<Result<SizedVec<_, { constants::OUT }>, AddressParseError>>()?;

        // FIXME: Check if correct
        let out_notes_with_index =
            next_index + 1..(next_index + out_notes.as_slice().len() as u64 + 1);
        let mut output_energy = Num::ZERO;
        for (note, note_index) in out_notes.iter().zip(out_notes_with_index) {
            output_energy += note.b.to_num() * Num::from(spend_interval_index - note_index);
        }

        let new_balance = if input_value.to_uint() >= output_value.to_uint() {
            input_value - output_value
        } else {
            return Err(CreateTxError::InsufficientBalance);
        };

        let out_account = Account {
            eta: keys.eta,
            i: BoundedNum::new(Num::from(spend_interval_index)),
            b: BoundedNum::new(new_balance),
            e: BoundedNum::new(input_energy),
            t: rng.gen(),
        };

        let out_account_hash = out_account.hash(&self.params);
        let nullifier = nullifier(out_account_hash, keys.eta, &self.params);

        let ciphertext = {
            let entropy: [u8; 32] = rng.gen();
            cipher::encrypt(
                &entropy,
                keys.eta,
                out_account,
                out_notes.as_slice(),
                &self.params,
            )
        };

        // Hash input account + notes filling remaining space with non-hashed zeroes
        let in_note_hashes = in_notes.iter().map(|(_, note)| note.hash(&self.params));
        let input_hashes: SizedVec<_, { constants::IN }> = [prev_account.hash(&self.params)]
            .iter()
            .copied()
            .chain(in_note_hashes)
            .chain((0..).map(|_| Num::ZERO))
            .take(constants::IN)
            .collect();

        // Same with output
        let out_note_hashes = out_notes.iter().map(|n| n.hash(&self.params));
        let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> = [out_account_hash]
            .iter()
            .copied()
            .chain(out_note_hashes)
            .chain((0..).map(|_| Num::ZERO))
            .take(constants::OUT + 1)
            .collect();

        let out_commit = out_commitment_hash(out_hashes.as_slice(), &self.params);
        let tx_hash = tx_hash(input_hashes.as_slice(), out_commit, &self.params);

        let delta = make_delta::<P::Fr>(
            input_value,
            input_energy,
            Num::from(spend_interval_index as u32),
        );

        let tree = &state.tree;
        let root: Num<P::Fr> = tree.get_root();

        let mut memo_data =
            Vec::with_capacity(data.as_ref().map(|d| d.len()).unwrap_or(0) + ciphertext.len());
        if let Some(data) = &mut data {
            memo_data.append(data);
        }
        memo_data.extend(&ciphertext);

        let memo_hash = keccak256(&memo_data);
        let memo = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&memo_hash)));

        let public = TransferPub::<P::Fr> {
            root,
            nullifier,
            out_commit,
            delta,
            memo,
        };

        let tx = Tx {
            input: (
                prev_account,
                in_notes
                    .iter()
                    .map(|(_, note)| note)
                    .cloned()
                    .chain((0..).map(|_| zero_note()))
                    .take(constants::IN)
                    .collect(),
            ),
            output: (out_account, out_notes),
        };

        // TODO: Create an abstraction for signatures
        // let sk = if let Some(f) = &self.sign_callback {
        //     f()
        // } else {
        //     keys.sk
        // };

        let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, &self.params);

        let note_proofs = in_notes
            .iter()
            .copied()
            .map(|(index, _note)| {
                tree.get_leaf_proof(index)
                    .ok_or_else(|| CreateTxError::ProofNotFound(index))
            })
            .chain((0..).map(|_| Ok(zero_proof())))
            .take(constants::IN)
            .collect::<Result<_, _>>()?;

        let secret = TransferSec::<P::Fr> {
            tx,
            in_proof: (
                tree.get_leaf_proof(state.latest_account_index)
                    .unwrap_or_else(zero_proof),
                note_proofs,
            ),
            eddsa_s: eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a: keys.a,
        };

        Ok(TransactionData {
            public,
            secret,
            ciphertext,
            memo: memo_data,
            out_hashes,
            output_energy,
            output_value,
        })
    }

    /// Cache account at specified index.
    pub fn add_account(&mut self, at_index: u64, account: Account<P::Fr>) {
        self.state.add_account(at_index, account)
    }

    /// Caches a note at specified index.
    /// Only cache received notes.
    pub fn add_received_note(&mut self, at_index: u64, note: Note<P::Fr>) {
        self.state.add_received_note(at_index, note)
    }

    /// Returns user's total balance (account + available notes).
    pub fn total_balance(&self) -> Num<P::Fr> {
        self.state.total_balance()
    }
}
