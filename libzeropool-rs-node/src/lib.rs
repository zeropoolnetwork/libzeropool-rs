use libzeropool_rs::libzeropool::constants;
use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::engines::Bn256;
use libzeropool_rs::libzeropool::native::params::{PoolBN256, PoolParams as PoolParamsTrait};
use neon::prelude::*;
use serde::Serialize;

mod helpers;
mod merkle;
mod params;
mod proof;
mod storage;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

#[allow(non_snake_case)]
#[derive(Serialize)]
struct Constants {
    HEIGHT: usize,
    IN: usize,
    OUTLOG: usize,
    OUT: usize,
}

#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    let constants = neon_serde::to_value(
        &mut cx,
        &Constants {
            HEIGHT: constants::HEIGHT,
            IN: constants::IN,
            OUTLOG: constants::OUTPLUSONELOG,
            OUT: constants::OUT,
        },
    )
    .unwrap();

    cx.export_value("Constants", constants)?;

    cx.export_function("readParamsFromBinary", params::from_binary)?;
    cx.export_function("readParamsFromFile", params::from_file)?;

    cx.export_function("proveTx", proof::prove_tx)?;
    cx.export_function("proveTree", proof::prove_tree)?;

    cx.export_function("merkleNew", merkle::merkle_new)?;
    cx.export_function("merkleGetRoot", merkle::merkle_get_root)?;
    cx.export_function("merkleGetNextIndex", merkle::merkle_get_next_index)?;
    cx.export_function("merkleGetNode", merkle::merkle_get_node)?;
    cx.export_function("merkleAddHash", merkle::merkle_add_hash)?;
    cx.export_function("merkleAppendHash", merkle::merkle_append_hash)?;
    cx.export_function("merkleGetProof", merkle::merkle_get_leaf_proof)?;
    cx.export_function("merkleGetCommitmentProof", merkle::merkle_get_commitment_proof)?;
    cx.export_function("merkleGetAllNodes", merkle::merkle_get_all_nodes)?;
    cx.export_function("merkleGetVirtualNode", merkle::merkle_get_virtual_node)?;

    cx.export_function("txStorageNew", storage::tx_storage_new)?;
    cx.export_function("txStorageAdd", storage::tx_storage_add)?;
    cx.export_function("txStorageDelete", storage::tx_storage_delete)?;
    cx.export_function("txStorageGet", storage::tx_storage_get)?;

    cx.export_function("helpersOutCommitment", helpers::out_commitment)?;
    cx.export_function("helpersParseDelta", helpers::parse_delta_string)?;
    cx.export_function("helpersNumToStr", helpers::num_to_str)?;

    Ok(())
}
