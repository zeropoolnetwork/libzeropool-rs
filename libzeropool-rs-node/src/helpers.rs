use std::convert::TryInto;
use std::str::FromStr;

use libzeropool_rs::libzeropool::constants::OUT;
use libzeropool_rs::libzeropool::fawkes_crypto::borsh::{BorshDeserialize, BorshSerialize};
use libzeropool_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool_rs::libzeropool::native::tx::{out_commitment_hash, parse_delta};
use libzeropool_rs::libzeropool::POOL_PARAMS;

use neon::prelude::*;
use neon::types::buffer::TypedArray;

use crate::Fr;

pub fn out_commitment(mut cx: FunctionContext) -> JsResult<JsValue> {
    let out_hashes = cx.argument::<JsArray>(0)?;

    let out_hashes: Vec<Handle<JsValue>> = out_hashes.to_vec(&mut cx)?;

    assert_eq!(out_hashes.len(), OUT + 1);

    let out_hashes: Vec<Num<Fr>> = out_hashes
        .iter()
        .map(|&val| {
            let buf = val.downcast::<JsBuffer, FunctionContext>(&mut cx).unwrap();
            Num::try_from_slice(buf.as_slice(&cx)).unwrap()
        })
        .collect();

    let commitment = out_commitment_hash(&out_hashes, &*POOL_PARAMS);

    let res = neon_serde::to_value(&mut cx, &commitment).unwrap();

    Ok(res)
}

pub fn parse_delta_string(mut cx: FunctionContext) -> JsResult<JsObject> {
    let delta_str_js = cx.argument::<JsString>(0)?;
    let delta_str = delta_str_js.value(&mut cx);

    let delta: Num<Fr> = Num::from_str(delta_str.as_str()).unwrap();

    let delta_params = parse_delta(delta);
    let value_int: i64 = delta_params.0.try_into().unwrap();
    let energy_int: i64 = delta_params.1.try_into().unwrap();
    let index_uint: u64 = delta_params.2.try_into().unwrap();
    let pool_id_uint: u64 = delta_params.3.try_into().unwrap();

    let v = neon_serde::to_value(&mut cx, &value_int).unwrap();
    let e = neon_serde::to_value(&mut cx, &energy_int).unwrap();
    let index = neon_serde::to_value(&mut cx, &index_uint).unwrap();
    let pool_id = neon_serde::to_value(&mut cx, &pool_id_uint).unwrap();

    let js_object = JsObject::new(&mut cx);
    js_object.set(&mut cx, "v", v)?;
    js_object.set(&mut cx, "e", e)?;
    js_object.set(&mut cx, "index", index)?;
    js_object.set(&mut cx, "poolId", pool_id)?;

    Ok(js_object)
}

pub fn num_to_str(mut cx: FunctionContext) -> JsResult<JsString> {
    let hash: Num<Fr> = {
        let buffer = cx.argument::<JsBuffer>(0)?;
        Num::try_from_slice(buffer.as_slice(&cx)).unwrap()
    };
    Ok(cx.string(hash.to_string()))
}

pub fn str_to_num(mut cx: FunctionContext) -> JsResult<JsBuffer> {
    let num_str_js = cx.argument::<JsString>(0)?;
    let num_str = num_str_js.value(&mut cx);

    let num: Num<Fr> = Num::from_str(num_str.as_str()).unwrap();

    let mut vec = vec![];
    num.serialize(&mut vec).unwrap();

    let buf = JsBuffer::external(&mut cx, vec);

    Ok(buf)
}
