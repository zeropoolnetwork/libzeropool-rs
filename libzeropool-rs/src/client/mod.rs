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
    #[error("Insufficient balance: sum of outputs is greater than sum of inputs: {0} > {1}")]
    InsufficientBalance(String, String),
}

#[derive(Serialize, Deserialize)]
pub struct TransactionData<Fr: PrimeField> {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub ciphertext: Vec<u8>,
    pub memo: Vec<u8>,
    pub out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxOutput<Fr: PrimeField> {
    pub to: String,
    pub amount: BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TxType<Fr: PrimeField> {
    Transfer(Vec<TxOutput<Fr>>),
    Deposit(BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>),
    Withdraw(BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>),
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

    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        let mut rng = CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
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
        tx: TxType<P::Fr>,
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

        let mut rng = CustomRng;
        let keys = self.keys.clone();
        let state = &self.state;

        let prev_account = state.latest_account.unwrap_or_else(|| Account {
            eta: keys.eta,
            i: BoundedNum::new(Num::ZERO),
            b: BoundedNum::new(Num::ZERO),
            e: BoundedNum::new(Num::ZERO),
            t: BoundedNum::new(Num::ZERO),
        });

        let next_usable_index = state.earliest_usable_index();

        // Fetch constants::IN usable notes from state
        let in_notes_original: Vec<(u64, Note<P::Fr>)> = state
            .txs
            .iter_slice(next_usable_index..=state.latest_note_index)
            .take(constants::IN)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(note) => Some((index, note)),
                _ => None,
            })
            .collect();

        let spend_interval_index = in_notes_original
            .last()
            .map(|(index, _)| *index)
            .unwrap_or(state.latest_note_index);

        // Calculate total balance (account + constants::IN notes).
        let mut input_value = prev_account.b.to_num();
        for (_index, note) in &in_notes_original {
            input_value += note.b.to_num();
        }

        let mut input_energy = prev_account.e.to_num();
        input_energy +=
            prev_account.b.to_num() * (Num::from(spend_interval_index) - prev_account.i.to_num());

        for (note_index, note) in &in_notes_original {
            input_energy += note.b.to_num() * Num::from(spend_interval_index - note_index);
        }

        let mut output_value = Num::ZERO;

        let out_notes: SizedVec<_, { constants::OUT }> = if let TxType::Transfer(outputs) = &tx {
            if outputs.len() >= constants::OUT {
                return Err(CreateTxError::TooManyOutputs {
                    max: constants::OUT,
                    got: outputs.len(),
                });
            }

            outputs
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
                .collect::<Result<SizedVec<_, { constants::OUT }>, AddressParseError>>()?
        } else {
            (0..).map(|_| zero_note()).take(constants::OUT).collect()
        };

        let mut delta_value = Num::ZERO;
        let new_balance = match &tx {
            TxType::Transfer(_) => {
                if input_value.to_uint() >= output_value.to_uint() {
                    input_value - output_value
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        output_value.to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Withdraw(amount) => {
                delta_value = -amount.to_num();
                if input_value.to_uint() + delta_value.to_uint() >= NumRepr::ZERO {
                    input_value + delta_value
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        delta_value.to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Deposit(amount) => {
                delta_value = amount.to_num();
                input_value + delta_value
            }
        };

        let out_account = Account {
            eta: keys.eta,
            i: BoundedNum::new(Num::from(spend_interval_index)),
            b: BoundedNum::new(new_balance),
            e: BoundedNum::new(input_energy),
            t: rng.gen(),
        };

        let in_account_hash = prev_account.hash(&self.params);
        let nullifier = nullifier(in_account_hash, keys.eta, &self.params);

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
        let owned_zero_notes = (0..).map(|_| {
            let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
            let p_d = derive_key_p_d::<P, P::Fr>(d.to_num(), keys.eta, &self.params).x;
            Note {
                d,
                p_d,
                b: BoundedNum::new(Num::ZERO),
                t: rng.gen(),
            }
        });
        let in_notes: SizedVec<Note<P::Fr>, { constants::IN }> = in_notes_original
            .iter()
            .map(|(_, note)| note)
            .cloned()
            .chain(owned_zero_notes)
            .take(constants::IN)
            .collect();
        let in_note_hashes = in_notes.iter().map(|note| note.hash(&self.params));
        let input_hashes: SizedVec<_, { constants::IN + 1 }> = [in_account_hash]
            .iter()
            .copied()
            .chain(in_note_hashes)
            .collect();

        // Same with output
        let out_account_hash = out_account.hash(&self.params);
        let out_note_hashes = out_notes.iter().map(|n| n.hash(&self.params));
        let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> = [out_account_hash]
            .iter()
            .copied()
            .chain(out_note_hashes)
            .collect();

        let out_commit = out_commitment_hash(out_hashes.as_slice(), &self.params);
        let tx_hash = tx_hash(input_hashes.as_slice(), out_commit, &self.params);

        let delta_index = state.latest_account_index.map_or(0, |i| {
            let leafs_num = (constants::OUT + 1) as u64;
            (i / leafs_num + 1) * leafs_num
        });
        let delta = make_delta::<P::Fr>(delta_value, input_energy, Num::from(delta_index));

        let tree = &state.tree;
        let root: Num<P::Fr> = tree.get_root();

        let mut memo_data = {
            let ciphertext_size = ciphertext.len();
            let data_size = data.as_ref().map(|d| d.len()).unwrap_or(0);
            Vec::with_capacity(ciphertext_size + data_size)
        };
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
            input: (prev_account, in_notes),
            output: (out_account, out_notes),
        };

        // TODO: Create an abstraction for signatures
        // let sk = if let Some(f) = &self.sign_callback {
        //     f()
        // } else {
        //     keys.sk
        // };

        let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, &self.params);

        let account_proof = state.latest_account_index.map_or_else(
            || Ok(zero_proof()),
            |i| tree.get_leaf_proof(i).ok_or_else(|| CreateTxError::ProofNotFound(i))
        )?;
        let note_proofs = in_notes_original
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
            in_proof: (account_proof, note_proofs),
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

#[cfg(test)]
mod tests {
    use super::*;
    use libzeropool::POOL_PARAMS;

    #[test]
    fn test_create_tx_deposit_zero() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        acc.create_tx(TxType::Deposit(BoundedNum::new(Num::ZERO)), None)
            .unwrap();
    }

    #[test]
    fn test_create_tx_deposit_one() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        acc.create_tx(TxType::Deposit(BoundedNum::new(Num::ONE)), None)
            .unwrap();
    }

    // It's ok to transfer 0 while balance = 0
    #[test]
    fn test_create_tx_transfer_zero() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        let addr = acc.generate_address();

        let out = TxOutput {
            to: addr,
            amount: BoundedNum::new(Num::ZERO),
        };

        acc.create_tx(TxType::Transfer(vec![out]), None).unwrap();
    }

    #[test]
    #[should_panic]
    fn test_create_tx_transfer_one_no_balance() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        let addr = acc.generate_address();

        let out = TxOutput {
            to: addr,
            amount: BoundedNum::new(Num::ONE),
        };

        acc.create_tx(TxType::Transfer(vec![out]), None).unwrap();
    }
}
