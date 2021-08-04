use crate::{
    params::Params,
    ts_types::{TransferPub, TransferSec, TreePub, TreeSec},
    Engine, Fr, PoolParams,
};
use libzeropool::{
    circuit::tree::tree_update,
    circuit::tx::c_transfer,
    fawkes_crypto::{
        backend::bellman_groth16::engines::Engine,
        backend::bellman_groth16::prover::Proof,
        backend::bellman_groth16::prover::{prove, Proof as SnarkProof},
        backend::bellman_groth16::Parameters,
        ff_uint::Num,
    },
    native::params::PoolParams,
    native::tree::{TreePub, TreeSec},
    native::tree::{TreePub as NativeTreePub, TreeSec as NativeTreeSec},
    native::tx::{TransferPub as NativeTransferPub, TransferSec as NativeTransferSec},
    native::tx::{TransferPub, TransferSec},
    POOL_PARAMS,
};

pub fn prove_tx<E: Engine>(
    params: &Parameters<E>,
    transfer_pub: TransferPub<E::Fr>,
    transfer_sec: TransferSec<E::Fr>,
) -> (Vec<Num<E::Fr>>, Proof<E>) {
    let circuit = |public, secret| {
        c_transfer(&public, &secret, params);
    };

    prove(params, &transfer_pub, &transfer_sec, circuit)
}

pub fn prove_tree<E: Engine>(
    params: &Parameters<E>,
    tree_pub: TreePub<E::Fr>,
    tree_sec: TreeSec<E::Fr>,
) -> (Vec<Num<E::Fr>>, Proof<E>) {
    let circuit = |public, secret| {
        tree_update(&public, &secret, params);
    };

    prove(params, &tree_pub, &tree_sec, circuit)
}
