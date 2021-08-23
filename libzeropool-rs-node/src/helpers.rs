use libzeropool_rs::libzeropool::constants::OUT;
use libzeropool_rs::libzeropool::fawkes_crypto::borsh::BorshDeserialize;
use libzeropool_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool_rs::libzeropool::native::tx::out_commitment_hash;
use libzeropool_rs::libzeropool::POOL_PARAMS;

use neon::prelude::*;

use crate::Fr;

pub fn out_commitment(mut cx: FunctionContext) -> JsResult<JsValue> {
    let out_hashes = cx.argument::<JsArray>(0)?;

    let out_hashes: Vec<Handle<JsValue>> = out_hashes.to_vec(&mut cx)?;

    assert_eq!(out_hashes.len(), OUT + 1);

    let out_hashes: Vec<Num<Fr>> = out_hashes
        .iter()
        .map(|&val| {
            let buf = val.downcast::<JsBuffer, FunctionContext>(&mut cx).unwrap();
            cx.borrow(&buf, |data| {
                Num::try_from_slice(data.as_slice()).unwrap()
            })
        })
        .collect();

    let commitment = out_commitment_hash(&out_hashes, &*POOL_PARAMS);

    let res = neon_serde::to_value(&mut cx, &commitment).unwrap();

    Ok(res)
}
