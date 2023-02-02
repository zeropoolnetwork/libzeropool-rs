use std::str::FromStr;

use libzeropool_rs::{
    keys::Keys,
    libzeropool::{fawkes_crypto::ff_uint::Num, POOL_PARAMS},
};
use neon::{
    prelude::FunctionContext,
    result::JsResult,
    types::{JsString, JsValue},
};

pub fn keys_derive(mut cx: FunctionContext) -> JsResult<JsValue> {
    let sk_js = cx.argument::<JsString>(0)?;
    let sk_str = sk_js.value(&mut cx);
    let sk = Num::from_str(&sk_str).unwrap();
    let keys = Keys::derive(sk, &*POOL_PARAMS);
    let res = neon_serde::to_value(&mut cx, &keys).unwrap();

    Ok(res)
}
