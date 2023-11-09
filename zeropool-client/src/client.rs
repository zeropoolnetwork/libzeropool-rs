use thiserror::Error;
use zeropool_state::{
    client::{state::State, TxOutput, TxType, UserAccount},
    libzeropool::{
        fawkes_crypto::{engines::U256, ff_uint::Num},
        native::params::PoolParams,
    },
    store::KeyValueDB,
};
use zeropool_state::client::state::Transaction::Account;
use zeropool_state::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use zeropool_state::libzeropool::fawkes_crypto::ff_uint::PrimeField;
use zeropool_state::libzeropool::native::boundednum::BoundedNum;
use zeropool_state::proof::prove_tx;

use crate::{backend::Backend, Engine, Fs, POOL_PARAMS, relayer::RelayerClient};
use crate::relayer::{ProofWithInputs, TxDataRequest};

pub struct ClientConfig {
    pub backend: Backend,
    pub token_address: String,
    pub denominator: U256,
    pub relayer_url: String,
    pub public_address: String,
}

pub struct Out {
    pub amount: U256,
    pub to: String,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Relayer error: {0}")]
    RelayerError(#[from] crate::relayer::RelayerError),

    #[error("In/out amount is too small")]
    AmountTooSmall,
}

type Result<T> = std::result::Result<T, Error>;

pub struct Client<D: KeyValueDB, P: PoolParams> {
    config: ClientConfig,
    relayer: RelayerClient,
    account: UserAccount<P>,
    state: State<D, P>,
    params: Parameters<Engine>,
}

impl<D: KeyValueDB, P: PoolParams> Client<D, P> {
    pub async fn new(sk: Num<Fs>, params: Parameters<Engine>, config: ClientConfig) -> Result<Self> {
        let account = UserAccount::new(sk, POOL_PARAMS.clone());
        let state = State::init_native(config.token_address.clone(), POOL_PARAMS.clone()).await?;

        Ok(Client {
            account,
            state,
            config,
            params,
            relayer: RelayerClient::new(&config.relayer_url).await?,
        })
    }

    pub async fn deposit<F: Fn(&[u8]) -> Vec<u8>>(
        &self,
        amount: U256,
        deposit_id: Option<u64>,
        outs: &[Out],
        sign: F,
    ) -> Result<u64> {
        if amount < self.config.denominator {
            return Err(Error::AmountTooSmall);
        }

        let amount_denominated = amount / self.config.denominator;

        let mut outs_denominated = Vec::with_capacity(outs.len());
        for out in outs {
            if out.amount < self.config.denominator {
                return Err(Error::AmountTooSmall);
            }

            outs_denominated.push(TxOutput {
                amount: out.amount / self.config.denominator,
                to: out.to.clone(),
            });
        }

        self.update_state().await?;
        let delta_index = 0; // FIXME

        let in_account = if let Some(acc) = self.state.latest_account() {
            Some((
                self.state
                    .latest_account_index
                    .expect("latest_account_index is None while latest_account is present"),
                acc,
            ))
        } else {
            None
        };

        let fee = Num::ZERO; // FIXME

        let in_notes = self.state.usable_notes();

        let tx_data = self.account.create_tx(
            TxType::Deposit {
                fee: fee.into(),
                deposit_amount: amount_denominated,
                outputs: outs_denominated,
            },
            in_account,
            in_notes,
            delta_index,
            &self.state.tree,
        )?;

        let proof = prove_tx(&self.params, &tx_data.public, &tx_data.secret)?;

        let deposit_data = self
            .config
            .backend
            .sign_deposit_data(tx_data.public.nullifier.0.to_uint(), &self.config.public_address, deposit_id.unwrap_or_default(),  &sign));

        let request = TxDataRequest {
            tx_type: crate::relayer::TxType::Deposit,
            proof: ProofWithInputs {
                proof: proof.0,
                inputs: proof.1,
            },
            memo: tx_data.memo,
            extra_data: Some(deposit_data),
        };

        let job_id = self.relayer.create_deposit(request).await?;

        Ok(job_id)
    }

    pub async fn transfer(&self, outs: &[Out]) -> Result<u64> {
        let mut outs_denominated = Vec::with_capacity(outs.len());
        for out in outs {
            if out.amount < self.config.denominator {
                return Err(Error::AmountTooSmall);
            }

            outs_denominated.push(TxOutput {
                amount: out.amount / self.config.denominator,
                to: out.to.clone(),
            });
        }

        self.update_state().await?;
        let delta_index = 0; // FIXME

        let in_account = if let Some(acc) = self.state.latest_account() {
            Some((
                self.state
                    .latest_account_index
                    .expect("latest_account_index is None while latest_account is present"),
                acc,
            ))
        } else {
            None
        };

        let fee = Num::ZERO; // FIXME

        let in_notes = self.state.usable_notes();

        let tx_data = self.account.create_tx(
            TxType::Transfer {
                fee: fee.into(),
                outputs: outs_denominated,
            },
            in_account,
            in_notes,
            delta_index,
            &self.state.tree,
        )?;

        let proof = prove_tx(&self.params, &tx_data.public, &tx_data.secret)?;

        let request = TxDataRequest {
            tx_type: crate::relayer::TxType::Transfer,
            proof: ProofWithInputs {
                proof: proof.0,
                inputs: proof.1,
            },
            memo: tx_data.memo,
            extra_data: None,
        };

        let job_id = self.relayer.create_deposit(request).await?;

        Ok(job_id)
    }

    pub async fn withdraw(&self, address: String, amount: U256) -> Result<u64> {
        if amount < self.config.denominator {
            return Err(Error::AmountTooSmall);
        }

        let amount_denominated = amount / self.config.denominator;

        self.update_state().await?;
        let delta_index = 0; // FIXME

        let in_account = if let Some(acc) = self.state.latest_account() {
            Some((
                self.state
                    .latest_account_index
                    .expect("latest_account_index is None while latest_account is present"),
                acc,
            ))
        } else {
            None
        };

        let fee = Num::ZERO; // FIXME

        let in_notes = self.state.usable_notes();

        let tx_data = self.account.create_tx(
            TxType::Withdraw {
                fee: fee.into(),
                withdraw_amount: amount_denominated,
                to: address.into_bytes(),
                native_amount: BoundedNum::new(Num::new(amount)),
                energy_amount: BoundedNum::new(Num::ZERO), // FIXME
            },
            in_account,
            in_notes,
            delta_index,
            &self.state.tree,
        )?;

        let proof = prove_tx(&self.params, &tx_data.public, &tx_data.secret)?;

        let request = TxDataRequest {
            tx_type: crate::relayer::TxType::Transfer,
            proof: ProofWithInputs {
                proof: proof.0,
                inputs: proof.1,
            },
            memo: tx_data.memo,
            extra_data: None,
        };

        let job_id = self.relayer.create_deposit(request).await?;

        Ok(job_id)
    }

    /// Fetch the latest state from the relayer.
    async fn update_state(&self) -> Result<()> {
        let info = self.relayer.get_info().await?;
        // TODO: Do rollback if we are ahead of the relayer's optimistic state.

        // if info.optimistic_index > self.state.tree.get_leave {
        //
        // }

        Ok(())
    }

    async fn rollback_state(&self, index: u64) -> Result<()> {
        self.state.rollback(index)
    }
}
