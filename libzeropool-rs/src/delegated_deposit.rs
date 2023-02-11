use libzeropool::{
    constants,
    fawkes_crypto::{
        core::sizedvec::SizedVec,
        ff_uint::{Num, NumRepr, PrimeField, Uint},
    },
    native::{
        boundednum::BoundedNum,
        delegated_deposit::{DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec},
        params::PoolParams,
        tx::out_commitment_hash,
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    client::CreateTxError,
    utils::{keccak256, zero_account, zero_note},
};

pub const DELEGATED_DEPOSIT_MAGIC: [u8; 4] = [0xff; 4];
pub const MEMO_DELEGATED_DEPOSIT_SIZE: usize = 8 + constants::DIVERSIFIER_SIZE_BITS / 8 + 32 + 8;

pub struct MemoDelegatedDeposit<Fr: PrimeField> {
    pub id: u64,
    pub receiver_d: BoundedNum<Fr, { constants::DIVERSIFIER_SIZE_BITS }>,
    pub receiver_p: Num<Fr>,
    pub denominated_amount: u64,
}

impl<Fr: PrimeField> MemoDelegatedDeposit<Fr> {
    pub fn write<W: std::io::Write>(&self, mut w: W) -> std::io::Result<()> {
        w.write_all(&self.id.to_be_bytes())?;
        w.write_all(&self.receiver_d.to_num().to_uint().0.to_big_endian()[22..])?;
        w.write_all(&self.receiver_p.to_uint().0.to_big_endian())?;
        w.write_all(&self.denominated_amount.to_be_bytes())?;
        Ok(())
    }

    pub fn read<R: std::io::Read>(mut r: R) -> std::io::Result<Self> {
        let mut id = [0u8; 8];
        r.read_exact(&mut id)?;
        let mut receiver_d = [0u8; constants::DIVERSIFIER_SIZE_BITS / 8];
        r.read_exact(&mut receiver_d)?;
        let mut receiver_p = [0u8; 32];
        r.read_exact(&mut receiver_p)?;
        let mut denominated_amount = [0u8; 8];
        r.read_exact(&mut denominated_amount)?;
        Ok(Self {
            id: u64::from_be_bytes(id),
            receiver_d: BoundedNum::new(Num::from_uint_reduced(NumRepr(Uint::from_big_endian(
                &receiver_d,
            )))),
            receiver_p: Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&receiver_p))),
            denominated_amount: u64::from_be_bytes(denominated_amount),
        })
    }

    pub fn to_delegated_deposit(&self) -> DelegatedDeposit<Fr> {
        DelegatedDeposit {
            d: self.receiver_d,
            p_d: self.receiver_p,
            b: BoundedNum::new(Num::from(self.denominated_amount)),
        }
    }
}

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
            b: BoundedNum::new(Num::from(self.denominated_amount)),
        }
    }

    pub fn to_memo_delegated_deposit(&self) -> MemoDelegatedDeposit<Fr> {
        MemoDelegatedDeposit {
            id: self.id,
            receiver_d: self.receiver_d,
            receiver_p: self.receiver_p,
            denominated_amount: self.denominated_amount - self.denominated_fee,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DelegatedDepositData<Fr: PrimeField> {
    pub public: DelegatedDepositBatchPub<Fr>,
    pub secret: DelegatedDepositBatchSec<Fr>,
    pub memo: Vec<u8>,
}

impl<Fr: PrimeField> DelegatedDepositData<Fr> {
    pub fn create<P>(
        deposits: &[FullDelegatedDeposit<P::Fr>],
        params: &P,
    ) -> Result<Self, CreateTxError>
    where
        P: PoolParams<Fr = Fr>,
    {
        if deposits.is_empty() {
            return Err(CreateTxError::TooFewOutputs { min: 1, got: 0 });
        }

        if deposits.len() > constants::DELEGATED_DEPOSITS_NUM {
            return Err(CreateTxError::TooManyOutputs {
                max: constants::DELEGATED_DEPOSITS_NUM,
                got: deposits.len(),
            });
        }

        // Zero account for delegated deposit
        let zero_account = zero_account();
        let zero_account_hash = zero_account.hash(params);
        let zero_note = zero_note();
        let zero_note_hash = zero_note.hash(params);

        let out_notes = deposits.iter().map(|d| d.to_delegated_deposit().to_note());
        let out_hashes: SizedVec<Num<P::Fr>, { constants::OUT + 1 }> =
            std::iter::once(zero_account_hash)
                .chain(out_notes.map(|n| n.hash(params)))
                .chain(std::iter::repeat(zero_note_hash))
                .take(constants::OUT + 1)
                .collect();

        let out_commitment_hash = out_commitment_hash(out_hashes.as_slice(), params);

        // keccak256(out_commitment_hash + deposits)
        let keccak_sum = {
            let mut data_for_keccak = Vec::new();
            data_for_keccak.extend_from_slice(&out_commitment_hash.to_uint().0.to_big_endian());
            for deposit in deposits {
                let deposit = deposit.to_delegated_deposit();
                data_for_keccak
                    .extend_from_slice(&deposit.d.to_num().to_uint().0.to_big_endian()[22..]);
                data_for_keccak.extend_from_slice(&deposit.p_d.to_uint().0.to_big_endian());
                data_for_keccak
                    .extend_from_slice(&deposit.b.to_num().to_uint().0.to_big_endian()[24..]);
            }
            Num::from_uint_reduced(NumRepr(Uint::from_big_endian(&keccak256(&data_for_keccak))))
        };

        let public = DelegatedDepositBatchPub { keccak_sum };
        let secret = DelegatedDepositBatchSec::<P::Fr> {
            out_commitment_hash,
            deposits: deposits
                .iter()
                .map(FullDelegatedDeposit::to_delegated_deposit)
                .chain(std::iter::repeat(DelegatedDeposit {
                    d: BoundedNum::new(Num::ZERO),
                    p_d: Num::ZERO,
                    b: BoundedNum::new(Num::ZERO),
                }))
                .take(constants::DELEGATED_DEPOSITS_NUM)
                .collect(),
        };

        let memo_data = {
            let memo_size = 4 + 58 * deposits.len();
            let mut data = Vec::with_capacity(memo_size);
            data.extend_from_slice(&DELEGATED_DEPOSIT_MAGIC);

            for deposit in deposits {
                deposit.to_memo_delegated_deposit().write(&mut data)?;
            }

            data
        };

        Ok(DelegatedDepositData {
            public,
            secret,
            memo: memo_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use libzeropool::{
        fawkes_crypto::backend::bellman_groth16::{engines::Bn256, verifier::verify, Parameters},
        POOL_PARAMS,
    };

    use super::*;
    use crate::proof::prove_delegated_deposit;

    #[test]
    #[ignore]
    fn test_delegated_deposit_data_create_full() {
        let dd_params_data = std::fs::read("../params/delegated_deposit_params.bin").unwrap();
        let dd_params =
            Parameters::<Bn256>::read(&mut dd_params_data.as_slice(), true, true).unwrap();
        let dd_vk = serde_json::from_str(
            &std::fs::read_to_string("../params/delegated_deposit_verification_key.json").unwrap(),
        )
        .unwrap();

        let d = DelegatedDepositData::create(
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
            &*POOL_PARAMS,
        )
        .unwrap();

        let (inputs, proof) =
            prove_delegated_deposit(&dd_params, &*POOL_PARAMS, d.public, d.secret);

        assert!(verify(&dd_vk, &proof, &inputs));
    }
}
