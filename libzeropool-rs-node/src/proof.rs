use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::prover::Proof as NativeProof;
use libzeropool_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool_rs::proof::{prove_tree, prove_tx};
use neon::prelude::*;

use crate::{Engine, Fr};

pub struct SnarkProof {
    inputs: Vec<Num<Fr>>,
    proof: NativeProof<Engine>,
}

declare_types! {
    pub class JsSnarkProof for SnarkProof {}
}

fn prove_tx_js(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    //
    let arg0 = cx.argument::<JsObject>(0)?;

    let js_value = neon_serde::to_value(&mut cx, &value)?;
    let pair = prove_tx(parameters, &*POOL_PARAMS);

    Ok(js_value)
}

fn prove_tree_js(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    Ok(cx.undefined())
}

register_module!(mut m, {
    m.export_function("proveTx", prove_tx_js)?;
    m.export_function("proveTree", prove_tree_js)?;
    Ok(())
});
