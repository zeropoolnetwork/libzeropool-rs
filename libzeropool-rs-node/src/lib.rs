use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use libzeropool_rs::libzeropool::native::params::{PoolBN256, PoolParams as PoolParamsTrait};
use neon::prelude::*;

mod client;
mod params;
// mod proof;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("fromBinary", params::from_binary)?;

    Ok(())
}
