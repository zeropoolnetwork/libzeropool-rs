use std::{
    convert::{TryFrom, TryInto},
    future::Future,
    io::Write,
};

use kvdb::KeyValueDB;
use libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
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
    merkle::Hash,
    random::CustomRng,
    utils::{keccak256, zero_note, zero_proof},
};

pub mod state;

#[derive(Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TxVersion {
    /// Original evm contract compatible version
    V1 = 1,
    /// Version with ciphertext length and nullifier signature
    V2,
}

impl TryFrom<u8> for TxVersion {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(TxVersion::V1),
            2 => Ok(TxVersion::V2),
            _ => Err(()),
        }
    }
}

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
    #[error("Insufficient energy: available {0}, received {1}")]
    InsufficientEnergy(String, String),
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct StateFragment<Fr: PrimeField> {
    pub new_leafs: Vec<(u64, Vec<Hash<Fr>>)>,
    pub new_commitments: Vec<(u64, Hash<Fr>)>,
    pub new_accounts: Vec<(u64, Account<Fr>)>,
    pub new_notes: Vec<(u64, Note<Fr>)>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransactionData<Fr: PrimeField> {
    pub public: TransferPub<Fr>,
    pub secret: TransferSec<Fr>,
    pub ciphertext: Vec<u8>,
    pub memo: Vec<u8>,
    pub commitment_root: Num<Fr>,
    pub out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }>,
}

pub type TokenAmount<Fr> = BoundedNum<Fr, { constants::BALANCE_SIZE_BITS }>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TxOutput<Fr: PrimeField> {
    pub to: String,
    pub amount: TokenAmount<Fr>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TxType<Fr: PrimeField> {
    Transfer {
        fee: TokenAmount<Fr>,
        data: Vec<u8>,
        outputs: Vec<TxOutput<Fr>>,
    },
    Deposit {
        fee: TokenAmount<Fr>,
        data: Vec<u8>,
        deposit_amount: TokenAmount<Fr>,
        outputs: Vec<TxOutput<Fr>>,
    },
    DepositPermittable {
        fee: TokenAmount<Fr>,
        data: Vec<u8>,
        deposit_amount: TokenAmount<Fr>,
        deadline: u64,
        holder: Vec<u8>,
        outputs: Vec<TxOutput<Fr>>,
    },
    Withdraw {
        fee: TokenAmount<Fr>,
        data: Vec<u8>,
        withdraw_amount: TokenAmount<Fr>,
        to: Vec<u8>,
        native_amount: TokenAmount<Fr>,
        energy_amount: TokenAmount<Fr>,
    },
}

pub struct UserAccount<D: KeyValueDB, P: PoolParams> {
    pub pool_id: BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
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
            // For now it is constant, but later should be provided by user
            pool_id: BoundedNum::new(Num::ZERO),
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

    fn generate_address_components(
        &self,
    ) -> (
        BoundedNum<P::Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
        Num<P::Fr>,
    ) {
        let mut rng = CustomRng;

        let d: BoundedNum<_, { constants::DIVERSIFIER_SIZE_BITS }> = rng.gen();
        let pk_d = derive_key_p_d(d.to_num(), self.keys.eta, &self.params);
        (d, pk_d.x)
    }

    /// Generates a new private address.
    pub fn generate_address(&self) -> String {
        let (d, p_d) = self.generate_address_components();

        format_address::<P>(d, p_d)
    }

    /// Attempts to decrypt notes.
    pub fn decrypt_notes(&self, data: Vec<u8>) -> Vec<Option<Note<P::Fr>>> {
        cipher::decrypt_in(self.keys.eta, &data, &self.params)
    }

    /// Attempts to decrypt account and notes.
    pub fn decrypt_pair(&self, data: Vec<u8>) -> Option<(Account<P::Fr>, Vec<Note<P::Fr>>)> {
        cipher::decrypt_out(self.keys.eta, &data, &self.params)
    }

    pub fn is_own_address(&self, address: &str) -> bool {
        let mut result = false;
        if let Ok((d, p_d)) = parse_address::<P>(address) {
            let own_p_d = derive_key_p_d(d.to_num(), self.keys.eta, &self.params).x;
            result = own_p_d == p_d;
        }

        result
    }

    /// Constructs a transaction.
    pub async fn create_tx<Fut, F>(
        &self,
        tx: TxType<P::Fr>,
        delta_index: Option<u64>,
        extra_state: Option<StateFragment<P::Fr>>,
        sign: Option<F>,
        tx_version: TxVersion,
    ) -> Result<TransactionData<P::Fr>, CreateTxError>
    where
        Fut: Future<Output = Vec<u8>>,
        F: FnOnce(&[u8]) -> Fut,
    {
        let mut rng = CustomRng;
        let keys = self.keys.clone();
        let state = &self.state;

        let extra_state = extra_state.unwrap_or(StateFragment {
            new_leafs: [].to_vec(),
            new_commitments: [].to_vec(),
            new_accounts: [].to_vec(),
            new_notes: [].to_vec(),
        });

        // initial input account (from optimistic state)
        let (in_account_optimistic_index, in_account_optimistic) = {
            let last_acc = extra_state.new_accounts.last();
            match last_acc {
                Some(last_acc) => (Some(last_acc.0), Some(last_acc.1)),
                _ => (None, None),
            }
        };

        // initial input account (from non-optimistic state)
        let in_account = in_account_optimistic.unwrap_or_else(|| {
            state.latest_account.unwrap_or_else(|| {
                // Initial account should have d = pool_id to protect from reply attacks
                let d = self.pool_id;
                let p_d = derive_key_p_d(d.to_num(), self.keys.eta, &self.params).x;
                Account {
                    d: self.pool_id,
                    p_d,
                    i: BoundedNum::new(Num::ZERO),
                    b: BoundedNum::new(Num::ZERO),
                    e: BoundedNum::new(Num::ZERO),
                }
            })
        });

        let tree = &self.state.tree;

        let in_account_index = in_account_optimistic_index.or(state.latest_account_index);

        // initial usable note index
        let next_usable_index = state
            .earliest_usable_index_optimistic(&extra_state.new_accounts, &extra_state.new_notes);

        let latest_note_index_optimistic = extra_state
            .new_notes
            .last()
            .map(|indexed_note| indexed_note.0)
            .unwrap_or(state.latest_note_index);

        // Should be provided by relayer together with note proofs, but as a fallback
        // take the next index of the tree (optimistic part included).
        let delta_index = Num::from(delta_index.unwrap_or_else(|| {
            let next_by_optimistic_leaf = extra_state.new_leafs.last().map(|leafs| {
                (((leafs.0 + (leafs.1.len() as u64)) >> constants::OUTPLUSONELOG) + 1)
                    << constants::OUTPLUSONELOG
            });
            let next_by_optimistic_commitment =
                extra_state.new_commitments.last().map(|commitment| {
                    ((commitment.0 >> constants::OUTPLUSONELOG) + 1) << constants::OUTPLUSONELOG
                });
            next_by_optimistic_leaf
                .into_iter()
                .chain(next_by_optimistic_commitment)
                .max()
                .unwrap_or(self.state.tree.next_index())
        }));

        let (fee, tx_data, user_data) = {
            let mut tx_data: Vec<u8> = vec![];
            match &tx {
                TxType::Deposit { fee, data, .. } => {
                    let raw_fee: u64 = fee.to_num().try_into().unwrap();
                    tx_data.write_all(&raw_fee.to_be_bytes()).unwrap();
                    (fee, tx_data, data)
                }
                TxType::DepositPermittable {
                    fee,
                    data,
                    deadline,
                    holder,
                    ..
                } => {
                    let raw_fee: u64 = fee.to_num().try_into().unwrap();

                    tx_data.write_all(&raw_fee.to_be_bytes()).unwrap();
                    tx_data.write_all(&deadline.to_be_bytes()).unwrap();
                    tx_data.append(&mut holder.clone());

                    (fee, tx_data, data)
                }
                TxType::Transfer { fee, data, .. } => {
                    let raw_fee: u64 = fee.to_num().try_into().unwrap();
                    tx_data.write_all(&raw_fee.to_be_bytes()).unwrap();
                    (fee, tx_data, data)
                }
                TxType::Withdraw {
                    fee,
                    data,
                    to,
                    native_amount,
                    ..
                } => {
                    let raw_fee: u64 = fee.to_num().try_into().unwrap();
                    let raw_native_amount: u64 = native_amount.to_num().try_into().unwrap();

                    tx_data.write_all(&raw_fee.to_be_bytes()).unwrap();
                    tx_data.write_all(&raw_native_amount.to_be_bytes()).unwrap();
                    tx_data.append(&mut to.clone());

                    (fee, tx_data, data)
                }
            }
        };

        // Optimistic available notes
        let optimistic_available_notes = extra_state
            .new_notes
            .into_iter()
            .filter(|indexed_note| indexed_note.0 >= next_usable_index);

        // Fetch constants::IN usable notes from state
        let in_notes_original: Vec<(u64, Note<P::Fr>)> = state
            .txs
            .iter_slice(next_usable_index..=state.latest_note_index)
            .filter_map(|(index, tx)| match tx {
                Transaction::Note(note) => Some((index, note)),
                _ => None,
            })
            .chain(optimistic_available_notes)
            .take(constants::IN)
            .collect();

        let spend_interval_index = in_notes_original
            .last()
            .map(|(index, _)| *index + 1)
            .unwrap_or(if latest_note_index_optimistic > 0 {
                latest_note_index_optimistic + 1
            } else {
                0
            });

        // Calculate total balance (account + constants::IN notes).
        let mut input_value = in_account.b.to_num();
        for (_index, note) in &in_notes_original {
            input_value += note.b.to_num();
        }

        let mut output_value = Num::ZERO;

        let (num_real_out_notes, out_notes) = match &tx {
            TxType::Transfer { outputs, .. }
            | TxType::Deposit { outputs, .. }
            | TxType::DepositPermittable { outputs, .. } => {
                if outputs.len() >= constants::OUT {
                    return Err(CreateTxError::TooManyOutputs {
                        max: constants::OUT,
                        got: outputs.len(),
                    });
                }

                let out_notes = outputs
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

                (outputs.len(), out_notes)
            }
            _ => (0, (0..).map(|_| zero_note()).take(constants::OUT).collect()),
        };

        let mut delta_value = -fee.as_num();
        // By default all account energy will be withdrawn on withdraw tx
        let mut delta_energy = Num::ZERO;

        let in_account_pos = in_account_index.unwrap_or(0);

        let mut input_energy = in_account.e.to_num();
        input_energy += in_account.b.to_num() * (delta_index - Num::from(in_account_pos));

        for (note_index, note) in &in_notes_original {
            input_energy += note.b.to_num() * (delta_index - Num::from(*note_index));
        }
        let new_balance = match &tx {
            TxType::Transfer { .. } => {
                if input_value.to_uint() >= (output_value + fee.as_num()).to_uint() {
                    input_value - output_value - fee.as_num()
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        (output_value + fee.as_num()).to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Withdraw {
                withdraw_amount,
                energy_amount,
                ..
            } => {
                let amount = withdraw_amount.to_num();
                let energy = energy_amount.to_num();

                if energy.to_uint() > input_energy.to_uint() {
                    return Err(CreateTxError::InsufficientEnergy(
                        input_energy.to_string(),
                        energy.to_string(),
                    ));
                }

                delta_energy -= energy;
                delta_value -= amount;

                if input_value.to_uint() >= amount.to_uint() {
                    input_value + delta_value
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        delta_value.to_string(),
                        input_value.to_string(),
                    ));
                }
            }
            TxType::Deposit { deposit_amount, .. }
            | TxType::DepositPermittable { deposit_amount, .. } => {
                delta_value += deposit_amount.to_num();
                let new_total_balance = input_value + delta_value;
                if new_total_balance.to_uint() >= output_value.to_uint() {
                    new_total_balance - output_value
                } else {
                    return Err(CreateTxError::InsufficientBalance(
                        output_value.to_string(),
                        new_total_balance.to_string(),
                    ));
                }
            }
        };

        let (d, p_d) = self.generate_address_components();
        let out_account = Account {
            d,
            p_d,
            i: BoundedNum::new(Num::from(spend_interval_index)),
            b: BoundedNum::new(new_balance),
            e: BoundedNum::new(delta_energy + input_energy),
        };

        let in_account_hash = in_account.hash(&self.params);
        let nullifier = nullifier(
            in_account_hash,
            keys.eta,
            in_account_pos.into(),
            &self.params,
        );

        let ciphertext = {
            let entropy: [u8; 32] = rng.gen();

            // No need to include all the zero notes in the encrypted transaction
            let out_notes = &out_notes[0..num_real_out_notes];

            cipher::encrypt(&entropy, keys.eta, out_account, out_notes, &self.params)
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

        let delta = make_delta::<P::Fr>(
            delta_value,
            delta_energy,
            delta_index,
            *self.pool_id.clone().as_num(),
        );

        // calculate virtual subtree from the optimistic state
        let new_leafs = extra_state.new_leafs.iter().cloned();
        let new_commitments = extra_state.new_commitments.iter().cloned();
        let (mut virtual_nodes, update_boundaries) =
            tree.get_virtual_subtree(new_leafs, new_commitments);

        let root: Num<P::Fr> = tree.get_root_optimistic(&mut virtual_nodes, &update_boundaries);

        let nullifier_signature = if let Some(sign) = sign {
            sign(&nullifier.to_uint().0.to_big_endian()).await
        } else {
            vec![]
        };

        // memo = tx_specific_data, ciphertext, user_defined_data
        let mut memo_data = {
            let tx_data_size = tx_data.len();
            let ciphertext_size = ciphertext.len();
            let signature_size = nullifier_signature.len();
            let user_data_size = user_data.len();
            Vec::with_capacity(tx_data_size + ciphertext_size + signature_size + user_data_size)
        };

        memo_data.extend(&tx_data);
        if tx_version == TxVersion::V2 {
            memo_data.extend(&(ciphertext.len() as u32).to_le_bytes());
        }
        memo_data.extend(&ciphertext);
        if tx_version == TxVersion::V2 {
            memo_data.extend(&nullifier_signature);
        }
        memo_data.extend(user_data);

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
            input: (in_account, in_notes),
            output: (out_account, out_notes),
        };

        let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, &self.params);

        let account_proof = in_account_index.map_or_else(
            || Ok(zero_proof()),
            |i| {
                tree.get_proof_optimistic_index(i, &mut virtual_nodes, &update_boundaries)
                    .ok_or(CreateTxError::ProofNotFound(i))
            },
        )?;
        let note_proofs = in_notes_original
            .iter()
            .copied()
            .map(|(index, _note)| {
                tree.get_proof_optimistic_index(index, &mut virtual_nodes, &update_boundaries)
                    .ok_or(CreateTxError::ProofNotFound(index))
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
            commitment_root: out_commit,
            out_hashes,
        })
    }
}

#[cfg(test)]
mod tests {
    use libzeropool::POOL_PARAMS;

    use super::*;

    #[test]
    fn test_create_tx_deposit_zero() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        acc.create_tx(
            TxType::Deposit {
                fee: BoundedNum::new(Num::ZERO),
                data: vec![],
                deposit_amount: BoundedNum::new(Num::ZERO),
                outputs: vec![],
            },
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_create_tx_deposit_one() {
        let state = State::init_test(POOL_PARAMS.clone());
        let acc = UserAccount::new(Num::ZERO, state, POOL_PARAMS.clone());

        acc.create_tx(
            TxType::Deposit {
                fee: BoundedNum::new(Num::ZERO),
                data: vec![],
                deposit_amount: BoundedNum::new(Num::ONE),
                outputs: vec![],
            },
            None,
            None,
        )
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

        acc.create_tx(
            TxType::Transfer {
                fee: BoundedNum::new(Num::ZERO),
                data: vec![],
                outputs: vec![out],
            },
            None,
            None,
        )
        .unwrap();
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

        acc.create_tx(
            TxType::Transfer {
                fee: BoundedNum::new(Num::ZERO),
                data: vec![],
                outputs: vec![out],
            },
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn test_user_account_is_own_address() {
        let acc_1 = UserAccount::new(
            Num::ZERO,
            State::init_test(POOL_PARAMS.clone()),
            POOL_PARAMS.clone(),
        );
        let acc_2 = UserAccount::new(
            Num::ONE,
            State::init_test(POOL_PARAMS.clone()),
            POOL_PARAMS.clone(),
        );

        let address_1 = acc_1.generate_address();
        let address_2 = acc_2.generate_address();

        assert!(acc_1.is_own_address(&address_1));
        assert!(acc_2.is_own_address(&address_2));

        assert!(!acc_1.is_own_address(&address_2));
        assert!(!acc_2.is_own_address(&address_1));
    }
}
