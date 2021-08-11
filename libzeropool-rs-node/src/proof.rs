use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::prover::Proof as NativeProof;
use libzeropool_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool_rs::libzeropool::POOL_PARAMS;
use libzeropool_rs::proof::{prove_tree, prove_tx};
use neon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::params::BoxedParams;
use crate::{Engine, Fr};

#[derive(Serialize, Deserialize)]
pub struct SnarkProof {
    inputs: Vec<Num<Fr>>,
    proof: NativeProof<Engine>,
}

impl Finalize for SnarkProof {}

pub fn js_prove_tx(mut cx: FunctionContext) -> JsResult<JsValue> {
    let params = cx.argument::<BoxedParams>(0)?;

    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let pair = prove_tx(&params.borrow().inner, &*POOL_PARAMS, tr_pub, tr_sec);

    let proof = SnarkProof {
        inputs: pair.0,
        proof: pair.1,
    };

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn js_prove_tree(mut cx: FunctionContext) -> JsResult<JsValue> {
    let params = cx.argument::<BoxedParams>(0)?;

    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let pair = prove_tree(&params.borrow().inner, &*POOL_PARAMS, tr_pub, tr_sec);

    let proof = SnarkProof {
        inputs: pair.0,
        proof: pair.1,
    };

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}
