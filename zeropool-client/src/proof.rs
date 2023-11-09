use zeropool_state::libzeropool::{
    circuit::{tree::tree_update, tx::c_transfer},
    fawkes_crypto::{
        backend::bellman_groth16::{
            prover::{prove, Proof as SnarkProof, Proof},
            verifier::{verify, VK},
            Parameters,
        },
        ff_uint::Num,
    },
    native::{
        tree::{TreePub, TreeSec},
        tx::{TransferPub, TransferSec},
    },
    POOL_PARAMS,
};

use crate::{Engine, Fr};

pub fn tx(
    params: &Parameters<Engine>,
    public: TransferPub<Fr>,
    secret: TransferSec<Fr>,
) -> (Vec<Num<Fr>>, Proof<Engine>) {
    let circuit = |public, secret| {
        c_transfer(&public, &secret, &*POOL_PARAMS);
    };

    prove(params, &public, &secret, circuit)
}

pub fn tree(
    params: &Parameters<Engine>,
    public: TreePub<Fr>,
    secret: TreeSec<Fr>,
) -> (Vec<Num<Fr>>, Proof<Engine>) {
    let circuit = |public, secret| {
        tree_update(&public, &secret, &*POOL_PARAMS);
    };

    let (inputs, snark_proof) = prove(params, &public, &secret, circuit);
}
