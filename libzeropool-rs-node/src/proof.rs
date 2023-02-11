use std::sync::Arc;

use libzeropool_rs::{
    libzeropool::{
        fawkes_crypto::{
            backend::bellman_groth16::{
                prover::Proof as NativeProof,
                verifier::{verify, VK},
            },
            ff_uint::Num,
        },
        POOL_PARAMS,
    },
    proof::{
        prove_delegated_deposit as prove_delegated_deposit_native, prove_tree as prove_tree_native,
        prove_tx as prove_tx_native,
    },
};
use neon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    params::{BoxedParams, Params},
    Engine, Fr,
};

#[derive(Serialize, Deserialize)]
pub struct SnarkProof {
    inputs: Vec<Num<Fr>>,
    proof: NativeProof<Engine>,
}

impl Finalize for SnarkProof {}

pub fn prove_tx_async(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let params: Arc<Params> = (*cx.argument::<BoxedParams>(0)?).clone();
    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    std::thread::spawn(move || {
        let pair = prove_tx_native(&params.inner, &*POOL_PARAMS, tr_pub, tr_sec);
        let proof = SnarkProof {
            inputs: pair.0,
            proof: pair.1,
        };

        deferred.settle_with(&channel, move |mut cx| {
            neon_serde::to_value(&mut cx, &proof).or_else(|err| cx.throw_error(err.to_string()))
        });
    });

    Ok(promise)
}

pub fn prove_tree_async(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let params: Arc<Params> = (*cx.argument::<BoxedParams>(0)?).clone();
    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    std::thread::spawn(move || {
        let pair = prove_tree_native(&params.inner, &*POOL_PARAMS, tr_pub, tr_sec);
        let proof = SnarkProof {
            inputs: pair.0,
            proof: pair.1,
        };

        deferred.settle_with(&channel, move |mut cx| {
            neon_serde::to_value(&mut cx, &proof).or_else(|err| cx.throw_error(err.to_string()))
        });
    });

    Ok(promise)
}

pub fn prove_delegated_deposit_async(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let params: Arc<Params> = (*cx.argument::<BoxedParams>(0)?).clone();
    let d_pub_js = cx.argument::<JsValue>(1)?;
    let d_sec_js = cx.argument::<JsValue>(2)?;
    let d_pub = neon_serde::from_value(&mut cx, d_pub_js).unwrap();
    let d_sec = neon_serde::from_value(&mut cx, d_sec_js).unwrap();

    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    std::thread::spawn(move || {
        let (inputs, proof) =
            prove_delegated_deposit_native(&params.inner, &*POOL_PARAMS, d_pub, d_sec);
        let proof = SnarkProof { inputs, proof };

        deferred.settle_with(&channel, move |mut cx| {
            neon_serde::to_value(&mut cx, &proof).or_else(|err| cx.throw_error(err.to_string()))
        });
    });

    Ok(promise)
}

pub fn prove_tx(mut cx: FunctionContext) -> JsResult<JsValue> {
    let params = cx.argument::<BoxedParams>(0)?;

    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let pair = prove_tx_native(&params.inner, &*POOL_PARAMS, tr_pub, tr_sec);

    let proof = SnarkProof {
        inputs: pair.0,
        proof: pair.1,
    };

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn prove_tree(mut cx: FunctionContext) -> JsResult<JsValue> {
    let params = cx.argument::<BoxedParams>(0)?;

    let tr_pub_js = cx.argument::<JsValue>(1)?;
    let tr_sec_js = cx.argument::<JsValue>(2)?;
    let tr_pub = neon_serde::from_value(&mut cx, tr_pub_js).unwrap();
    let tr_sec = neon_serde::from_value(&mut cx, tr_sec_js).unwrap();

    let pair = prove_tree_native(&params.inner, &*POOL_PARAMS, tr_pub, tr_sec);

    let proof = SnarkProof {
        inputs: pair.0,
        proof: pair.1,
    };

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn prove_delegated_deposit(mut cx: FunctionContext) -> JsResult<JsValue> {
    let params = cx.argument::<BoxedParams>(0)?;

    let d_pub_js = cx.argument::<JsValue>(1)?;
    let d_sec_js = cx.argument::<JsValue>(2)?;
    let d_pub = neon_serde::from_value(&mut cx, d_pub_js).unwrap();
    let d_sec = neon_serde::from_value(&mut cx, d_sec_js).unwrap();

    let (inputs, proof) =
        prove_delegated_deposit_native(&params.inner, &*POOL_PARAMS, d_pub, d_sec);

    let proof = SnarkProof { inputs, proof };

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn verify_proof(mut cx: FunctionContext) -> JsResult<JsValue> {
    let vk_js = cx.argument::<JsValue>(0)?;
    let proof_js = cx.argument::<JsValue>(1)?;
    let inputs_js = cx.argument::<JsValue>(2)?;

    let vk: VK<Engine> = neon_serde::from_value(&mut cx, vk_js).unwrap();
    let proof = neon_serde::from_value(&mut cx, proof_js).unwrap();
    let inputs: Vec<Num<Fr>> = neon_serde::from_value(&mut cx, inputs_js).unwrap();

    let verfify_res = verify(&vk, &proof, &inputs);

    let result = neon_serde::to_value(&mut cx, &verfify_res).unwrap();

    Ok(result)
}
