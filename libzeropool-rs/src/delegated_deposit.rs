use libzeropool::{
    constants,
    fawkes_crypto::{
        backend::bellman_groth16::{engines::Engine, Parameters},
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
        rand::Rng,
    },
    native::{
        boundednum::BoundedNum,
        delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec},
        note::Note,
        params::PoolParams,
        tx::{
            make_delta, nullifier, out_commitment_hash, tx_hash, tx_sign, TransferPub, TransferSec,
            Tx,
        },
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    client::CreateTxError,
    keys::Keys,
    proof::prove_delegated_deposit,
    random::CustomRng,
    utils::{keccak256, zero_account, zero_note, zero_proof},
};

pub const DELEGATED_DEPOSIT_MAGIC: [u8; 4] = [0xff; 4];
pub const FULL_DELEGATED_DEPOSIT_SIZE: usize = 94;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))]
pub struct FullDelegatedDeposit<Fr: PrimeField> {
    pub id: u64,
    #[serde(with = "hex")]
    pub owner: Vec<u8>,
    pub receiver_d: BoundedNum<Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    pub receiver_p: Num<Fr>,
    pub denominated_amount: u64,
    pub denominated_fee: u64,
    pub expired: u64,
}

impl<Fr: PrimeField> FullDelegatedDeposit<Fr> {
    pub fn to_delegated_deposit(&self) -> DelegatedDeposit<Fr> {
        DelegatedDeposit {
            d: self.receiver_d,
            p_d: self.receiver_p,
            b: BoundedNum::new(Num::from(self.denominated_amount - self.denominated_fee)),
        }
    }

    pub fn write<W: std::io::Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.id.to_be_bytes())?;
        w.write_all(&self.owner)?;
        w.write_all(&self.receiver_d.to_num().to_uint().0.to_big_endian()[22..])?;
        w.write_all(&self.receiver_p.to_uint().0.to_big_endian())?;
        w.write_all(&self.denominated_amount.to_be_bytes())?;
        w.write_all(&self.denominated_fee.to_be_bytes())?;
        w.write_all(&self.expired.to_be_bytes())?;
        Ok(())
    }

    pub fn read<R: std::io::Read>(mut r: R) -> std::io::Result<Self> {
        let mut id = [0u8; 8];
        r.read_exact(&mut id)?;
        let mut owner = vec![0u8; 20];
        r.read_exact(&mut owner)?;
        let mut receiver_d = [0u8; 32];
        r.read_exact(&mut receiver_d)?;
        let mut receiver_p = [0u8; 32];
        r.read_exact(&mut receiver_p)?;
        let mut denominated_amount = [0u8; 8];
        r.read_exact(&mut denominated_amount)?;
        let mut denominated_fee = [0u8; 8];
        r.read_exact(&mut denominated_fee)?;
        let mut expired = [0u8; 8];
        r.read_exact(&mut expired)?;
        Ok(Self {
            id: u64::from_be_bytes(id),
            owner,
            receiver_d: BoundedNum::new(Num::from_uint_reduced(NumRepr(Uint::from_big_endian(
                &receiver_d,
            )))),
            receiver_p: Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&receiver_p))),
            denominated_amount: u64::from_be_bytes(denominated_amount),
            denominated_fee: u64::from_be_bytes(denominated_fee),
            expired: u64::from_be_bytes(expired),
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct DelegatedDepositData<Fr: PrimeField> {
    pub public: DelegatedDepositBatchPub<Fr>,
    pub secret: DelegatedDepositBatchSec<Fr>,
    pub memo: Vec<u8>,
    pub tx_public: TransferPub<Fr>,
    pub tx_secret: TransferSec<Fr>,
}

pub fn create_delegated_deposit_tx<P, E>(
    deposits: &[FullDelegatedDeposit<P::Fr>],
    root: Num<P::Fr>,
    pool_id: Num<P::Fr>,
    params: &P,
    dd_params: &Parameters<E>,
) -> Result<DelegatedDepositData<P::Fr>, CreateTxError>
where
    P: PoolParams<Fr = E::Fr>,
    E: Engine,
{
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

    let mut total_fee = Num::<P::Fr>::ZERO;
    let out_notes = deposits
        .iter()
        .map(|d| {
            total_fee += Num::from(d.denominated_fee);
            d.to_delegated_deposit().to_note()
        })
        .chain((0..).map(|_| zero_note))
        .take(constants::DELEGATED_DEPOSITS_NUM)
        .collect::<SizedVec<Note<P::Fr>, { constants::DELEGATED_DEPOSITS_NUM }>>();

    let nullifier = nullifier(zero_account_hash, keys.eta, Num::ZERO, params);

    let out_note_hashes = out_notes.iter().map(|n| n.hash(params));
    let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> = [zero_account_hash]
        .iter()
        .copied()
        .chain(out_note_hashes)
        .chain((0..).map(|_| zero_note_hash))
        .take(constants::OUT + 1)
        .collect();

    let out_commitment_hash = out_commitment_hash(out_hashes.as_slice(), params);

    let mut data_for_keccak = Vec::new();
    data_for_keccak.extend_from_slice(&out_commitment_hash.to_uint().0.to_big_endian());
    data_for_keccak.extend_from_slice(&zero_account_hash.to_uint().0.to_big_endian());
    for deposit in deposits {
        let deposit = deposit.to_delegated_deposit();
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
        deposits: deposits
            .iter()
            .map(FullDelegatedDeposit::to_delegated_deposit)
            .chain((0..).map(|_| DelegatedDeposit {
                d: BoundedNum::new(Num::ZERO),
                p_d: Num::ZERO,
                b: BoundedNum::new(Num::ZERO),
            }))
            .take(constants::DELEGATED_DEPOSITS_NUM)
            .collect(),
    };

    let (_, dd_proof) = prove_delegated_deposit(dd_params, params, public.clone(), secret.clone());

    let memo_data = {
        let memo_size = 8 + 256 + 4 + 32 + 94 * deposits.len();
        let mut data = Vec::with_capacity(memo_size);
        data.extend_from_slice(&total_fee.to_uint().0.to_big_endian());

        // write proof
        data.extend_from_slice(&dd_proof.a.0.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.a.1.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.b.0 .0.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.b.0 .1.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.b.1 .0.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.b.1 .1.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.c.0.to_uint().0.to_big_endian());
        data.extend_from_slice(&dd_proof.c.1.to_uint().0.to_big_endian());

        data.extend_from_slice(&DELEGATED_DEPOSIT_MAGIC);
        data.extend_from_slice(&zero_account_hash.to_uint().0.to_big_endian());

        for deposit in deposits {
            deposit.write(&mut data).unwrap();
        }

        data
    };
    let memo_hash = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&keccak256(&memo_data))));

    // Stuff for generating the general transfer proof
    let (tx_public, tx_secret) = {
        let in_notes_tx = (0..).map(|_| zero_note).take(constants::IN).collect();
        let in_note_hashes_tx = (0..).map(|_| zero_note_hash).take(constants::IN);
        let out_notes_tx = out_notes
            .iter()
            .copied()
            .chain((0..).map(|_| zero_note))
            .take(constants::OUT)
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
        memo: memo_data,
        tx_public,
        tx_secret,
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use libzeropool::{fawkes_crypto::backend::bellman_groth16::engines::Bn256, POOL_PARAMS};

    use super::*;

    #[test]
    #[ignore]
    fn test_create_delegated_deposit() {
        let data = std::fs::read("../params/delegated_deposit_params.bin").unwrap();
        let dd_params = Parameters::<Bn256>::read(&mut data.as_slice(), true, true).unwrap();

        let root = Num::from_str(
            "9405296262516531248577889588869366684428146101055546785269573509451581757964",
        )
        .unwrap();

        let d = create_delegated_deposit_tx(
            &[FullDelegatedDeposit {
                id: 0,
                owner: vec![0; 20],
                receiver_d: BoundedNum::new(Num::from_str("254501365180353910541213").unwrap()),
                receiver_p: Num::from_str(
                    "1518610811376102436745659088373274425162017815402814928120935968131387562269",
                )
                .unwrap(),
                denominated_amount: 500000000,
                denominated_fee: 0,
                expired: 1675838609,
            }],
            root,
            Num::ZERO,
            &*POOL_PARAMS,
            &dd_params,
        );

        assert!(true);
    }
}
