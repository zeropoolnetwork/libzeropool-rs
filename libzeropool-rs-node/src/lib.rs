use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use libzeropool_rs::libzeropool::native::params::{PoolBN256, PoolParams as PoolParamsTrait};
use neon::prelude::*;

mod client;
mod merkle;
mod params;
mod proof;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

// TODO: Nested modules
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    cx.export_function("readParamsFromBinary", params::from_binary)?;

    cx.export_function("proveTx", proof::js_prove_tx)?;
    cx.export_function("proveTree", proof::js_prove_tree)?;

    cx.export_function("merkleNew", merkle::merkle_new)?;
    cx.export_function("merkleAddHash", merkle::merkle_add_hash)?;
    cx.export_function("merkleGetProof", merkle::merkle_get_proof)?;

    Ok(())
}
