use kvdb::KeyValueDB;
use libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, Uint},
        rand::Rng,
    },
    native::{
        boundednum::BoundedNum,
        cipher,
        delegated_deposit::DelegatedDeposit,
        params::PoolParams,
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub, TransferSec,
            Tx,
        },
    },
};

use crate::{
    client::{CreateTxError, TransactionData},
    keys::Keys,
    random::CustomRng,
    utils::{keccak256, zero_account, zero_note, zero_proof},
};

pub fn create_delegated_deposit_tx<P: PoolParams, D: KeyValueDB>(
    deposits: &[DelegatedDeposit<P::Fr>],
    root: Num<P::Fr>,
    keys: Keys<P>,
    pool_id: BoundedNum<P::Fr, { constants::POOLID_SIZE_BITS }>,
    params: &P,
) -> Result<TransactionData<P::Fr>, CreateTxError> {
    if deposits.len() > constants::OUT {
        return Err(CreateTxError::TooManyOutputs {
            max: constants::OUT,
            got: deposits.len(),
        });
    }

    let mut rng = CustomRng;

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
        .take(constants::OUT)
        .collect::<SizedVec<_, { constants::OUT }>>();

    let nullifier = nullifier(zero_account_hash, keys.eta, Num::ZERO, params);

    let ciphertext = {
        let entropy: [u8; 32] = rng.gen();

        // No need to include all the zero notes in the encrypted transaction
        let out_notes = &out_notes[0..num_real_out_notes];

        cipher::encrypt(&entropy, keys.eta, zero_account, out_notes, params)
    };

    let in_notes = (0..).map(|_| zero_note).take(constants::IN).collect();
    let in_note_hashes = (0..).map(|_| zero_note_hash).take(constants::IN);

    let input_hashes: SizedVec<_, { constants::IN + 1 }> = [zero_account_hash]
        .iter()
        .copied()
        .chain(in_note_hashes)
        .collect();

    let out_note_hashes = out_notes.iter().map(|n| n.hash(params));
    let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> = [zero_account_hash]
        .iter()
        .copied()
        .chain(out_note_hashes)
        .collect();

    let out_commit = out_commitment_hash(out_hashes.as_slice(), params);
    let tx_hash = tx_hash(input_hashes.as_slice(), out_commit, params);

    let delta = make_delta::<P::Fr>(Num::ZERO, Num::ZERO, Num::ZERO, *pool_id.as_num());
    let memo_data = ciphertext.clone();
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
        input: (zero_account, in_notes),
        output: (zero_account, out_notes),
    };

    let (eddsa_s, eddsa_r) = tx_sign(keys.sk, tx_hash, params);

    let account_proof = zero_proof();
    let note_proofs = (0..)
        .map(|_| zero_proof())
        .take(constants::IN)
        .collect::<SizedVec<_, { constants::IN }>>();

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
