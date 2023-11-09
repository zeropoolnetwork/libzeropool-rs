use reqwest::Url;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeropool_state::libzeropool::fawkes_crypto::{
    backend::bellman_groth16::prover::Proof, ff_uint::Num,
};

use crate::{Engine, Fr};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    pub api_version: String,
    pub root: String,
    pub optimistic_root: String,
    pub pool_index: String,
    pub optimistic_index: String,
}

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStatusResponse {
    state: JobStatus, // tx_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
#[repr(u16)]
pub enum TxType {
    #[serde(rename = "0000")]
    Deposit = 0,
    #[serde(rename = "0001")]
    Transfer = 1,
    #[serde(rename = "0002")]
    Withdraw = 2,
}

#[derive(Serialize, Deserialize)]
pub struct ProofWithInputs {
    pub proof: Proof<Engine>,
    pub inputs: Vec<Num<Fr>>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TxDataRequest {
    pub tx_type: TxType,
    pub proof: ProofWithInputs,
    #[serde(with = "hex")]
    pub memo: Vec<u8>,
    #[serde(with = "hex")]
    pub extra_data: Option<Vec<u8>>,
}

#[derive(Error, Debug)]
pub enum RelayerError {
    ReqwestError(#[from] reqwest::Error),
    UnsupportedRelayerApiVersion,
}

type Result<T> = std::result::Result<T, RelayerError>;

pub struct RelayerTx {
    pub tx_hash: Vec<u8>,
    pub commitment: Num<Fr>,
    pub memo: Vec<u8>,
}

#[derive(Serialize)]
struct Hex(#[serde(with = "hex")] Vec<u8>);

pub struct RelayerClient {
    url: Url,
}

impl RelayerClient {
    pub async fn new(url: &str) -> Result<Self> {
        let url = Url::parse(url)?;

        let info = reqwest::get(url.join("info")?)
            .await?
            .json::<InfoResponse>()
            .await?;

        if info.api_version != "3" {
            return Err(RelayerError::UnsupportedRelayerApiVersion);
        }

        Ok(Self { url })
    }

    pub async fn get_info(&self) -> Result<InfoResponse> {
        let resp = reqwest::get(self.url.join("info")?).await?;
        let info = resp.json::<InfoResponse>().await?;
        Ok(info)
    }

    pub async fn job_status(&self, id: u64) -> Result<Option<JobStatus>> {
        let url = self.url.join("job")?.join(&id.to_string())?;
        let resp = reqwest::get(url).await?;
        let status = resp.json::<JobStatusResponse>().await?.state;
        Ok(Some(status))
    }

    pub async fn get_transactions(&self) -> Result<Vec<Vec<u8>>> {
        let url = self.url.join("transactions")?;
        let resp = reqwest::get(url).await?;
        let txs = resp.json::<Vec<Vec<u8>>>().await?;
        Ok(txs)
    }

    pub async fn create_transaction(&self, tx: TxDataRequest) -> Result<u64> {
        let url = self.url.join("transactions")?;
        let res = reqwest::Client::new().post(url).json(&tx).send().await?;
        let id = res.json::<u64>().await?;
        Ok(id)
    }
}
