use libzeropool::{
    circuit::{tree::tree_update, tx::c_transfer},
    fawkes_crypto::{
        backend::plonk::{
            engines::{Bn256, Engine},
            prover::{prove, Proof},
            setup::ProvingKey,
            Parameters,
        },
        ff_uint::Num,
    },
    native::{
        params::PoolParams,
        tree::{TreePub, TreeSec},
        tx::{TransferPub, TransferSec},
    },
};

pub fn prove_tx<P>(
    params: &Parameters<Bn256>,
    pk: &ProvingKey<Bn256>,
    pool_params: &P,
    transfer_pub: TransferPub<<Bn256 as Engine>::Fr>,
    transfer_sec: TransferSec<<Bn256 as Engine>::Fr>,
) -> (Vec<Num<<Bn256 as Engine>::Fr>>, Proof)
where
    P: PoolParams<Fr = <Bn256 as Engine>::Fr>,
{
    let circuit = |public, secret| {
        c_transfer(&public, &secret, pool_params);
    };

    prove(params, pk, &transfer_pub, &transfer_sec, circuit)
}

pub fn prove_tree<P>(
    params: &Parameters<Bn256>,
    pk: &ProvingKey<Bn256>,
    pool_params: &P,
    tree_pub: TreePub<<Bn256 as Engine>::Fr>,
    tree_sec: TreeSec<<Bn256 as Engine>::Fr>,
) -> (Vec<Num<<Bn256 as Engine>::Fr>>, Proof)
where
    P: PoolParams<Fr = <Bn256 as Engine>::Fr>,
{
    let circuit = |public, secret| {
        tree_update(&public, &secret, pool_params);
    };

    prove(params, pk, &tree_pub, &tree_sec, circuit)
}
