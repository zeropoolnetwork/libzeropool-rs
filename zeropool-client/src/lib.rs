pub use zeropool_state::libzeropool::POOL_PARAMS;
use zeropool_state::libzeropool::{
    fawkes_crypto::backend::bellman_groth16::engines::Bn256,
    native::params::{PoolBN256, PoolParams as PoolParamsTrait},
};

mod backend;
mod client;
mod proof;
mod relayer;
mod tx_parser;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;
