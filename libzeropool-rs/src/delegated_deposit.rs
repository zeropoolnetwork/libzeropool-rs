use libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
        rand::Rng,
    },
    native::{
        cipher,
        delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec},
        params::PoolParams,
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub, TransferSec,
            Tx,
        },
    },
};

use crate::{
    client::CreateTxError,
    keys::Keys,
    random::CustomRng,
    utils::{keccak256, zero_account, zero_note, zero_proof},
};

pub struct DelegatedDepositData<Fr: PrimeField> {
    pub public: DelegatedDepositBatchPub<Fr>,
    pub secret: DelegatedDepositBatchSec<Fr>,
    pub ciphertext: Vec<u8>,
    pub memo: Vec<u8>,
    pub out_hashes: SizedVec<Num<Fr>, { constants::DELEGATED_DEPOSITS_NUM + 1 }>,
    pub tx_public: TransferPub<Fr>,
    pub tx_secret: TransferSec<Fr>,
}

pub fn create_delegated_deposit_tx<P: PoolParams>(
    deposits: &[DelegatedDeposit<P::Fr>],
    root: Num<P::Fr>,
    pool_id: Num<P::Fr>,
    params: &P,
) -> Result<DelegatedDepositData<P::Fr>, CreateTxError> {
    if deposits.len() > constants::DELEGATED_DEPOSITS_NUM {
        return Err(CreateTxError::TooManyOutputs {
            max: constants::DELEGATED_DEPOSITS_NUM,
            got: deposits.len(),
        });
    }

    let mut rng = CustomRng;

    let keys = Keys::derive(rng.gen(), params);

    // Zero account for delegated deposit
    let zero_account = zero_account();
    let zero_account_hash = zero_account.hash(params);
    let zero_note = zero_note();
    let zero_note_hash = zero_note.hash(params);

    let num_real_out_notes = deposits.len();
    let out_notes = deposits
        .iter()
        .map(DelegatedDeposit::to_note)
        .chain((0..).map(|_| zero_note))
        .take(constants::DELEGATED_DEPOSITS_NUM)
        .collect::<SizedVec<_, { constants::DELEGATED_DEPOSITS_NUM }>>();

    let nullifier = nullifier(zero_account_hash, keys.eta, Num::ZERO, params);

    let ciphertext = {
        let entropy: [u8; 32] = rng.gen();

        // No need to include all the zero notes in the encrypted transaction
        let out_notes = &out_notes[0..num_real_out_notes];
        cipher::encrypt(&entropy, keys.eta, zero_account, out_notes, params)
    };

    let out_note_hashes = out_notes.iter().map(|n| n.hash(params));
    let out_hashes: SizedVec<Num<P::Fr>, { constants::DELEGATED_DEPOSITS_NUM + 1 }> =
        [zero_account_hash]
            .iter()
            .copied()
            .chain(out_note_hashes)
            .collect();

    let out_commitment_hash = out_commitment_hash(out_hashes.as_slice(), params);

    let memo_data = ciphertext.clone();
    let memo_hash = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&keccak256(&memo_data))));

    let mut data_for_keccak = Vec::new();
    data_for_keccak.extend_from_slice(&out_commitment_hash.to_uint().0.to_big_endian());
    data_for_keccak.extend_from_slice(&zero_account_hash.to_uint().0.to_big_endian());
    for deposit in deposits {
        data_for_keccak.extend_from_slice(&deposit.d.to_num().to_uint().0.to_big_endian());
        data_for_keccak.extend_from_slice(&deposit.p_d.to_uint().0.to_big_endian());
        data_for_keccak.extend_from_slice(&deposit.b.to_num().to_uint().0.to_big_endian());
    }

    let keccak_sum =
        Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&keccak256(&data_for_keccak))));

    let public = DelegatedDepositBatchPub {
        keccak_sum, // keccak256(out_commitment_hash + account + deposits)
    };

    let secret = DelegatedDepositBatchSec::<P::Fr> {
        out_account: zero_account,
        out_commitment_hash,
        deposits: deposits.iter().cloned().collect(),
    };

    // Stuff for generating the general transfer proof
    let (tx_public, tx_secret) = {
        let in_notes_tx = (0..).map(|_| zero_note).take(constants::IN).collect();
        let in_note_hashes_tx = (0..).map(|_| zero_note_hash).take(constants::IN);
        let out_notes_tx = out_notes
            .iter()
            .copied()
            .chain((0..).map(|_| zero_note))
            .take(constants::IN)
            .collect();

        let input_hashes_tx: SizedVec<_, { constants::IN + 1 }> = [zero_account_hash]
            .iter()
            .copied()
            .chain(in_note_hashes_tx)
            .collect();

        let tx = Tx {
            input: (zero_account, in_notes_tx),
            output: (zero_account, out_notes_tx),
        };

        let tx_hash = tx_hash(input_hashes_tx.as_slice(), out_commitment_hash, params);
        let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, params);

        let delta = make_delta::<P::Fr>(Num::ZERO, Num::ZERO, Num::ZERO, pool_id);
        let tx_public = TransferPub {
            root,
            nullifier,
            out_commit: out_commitment_hash,
            delta,
            memo: memo_hash,
        };

        let account_proof = zero_proof();
        let note_proofs = (0..)
            .map(|_| zero_proof())
            .take(constants::IN)
            .collect::<SizedVec<_, { constants::IN }>>();

        let tx_secret = TransferSec {
            tx,
            in_proof: (account_proof, note_proofs),
            eddsa_s: eddsa_s.to_other().unwrap(),
            eddsa_r,
            eddsa_a: keys.a,
        };

        (tx_public, tx_secret)
    };

    Ok(DelegatedDepositData {
        public,
        secret,
        ciphertext,
        memo: memo_data,
        out_hashes,
        tx_public,
        tx_secret,
    })
}
