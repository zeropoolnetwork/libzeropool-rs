use std::path::PathBuf;
use std::sync::Arc;

use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use neon::{prelude::*, types::buffer::TypedArray};

use crate::Engine;

pub type BoxedParams = JsBox<Arc<Params>>;
pub struct Params {
    pub inner: Parameters<Engine>,
}

pub fn from_binary(mut cx: FunctionContext) -> JsResult<BoxedParams> {
    let input = cx.argument::<JsBuffer>(0)?;

    let mut data = input.as_slice(&cx);
    let inner = Parameters::read(&mut data, true, true).unwrap();

    Ok(cx.boxed(Arc::new(Params { inner })))
}

pub fn from_file(mut cx: FunctionContext) -> JsResult<BoxedParams> {
    let path: PathBuf = {
        let path = cx.argument::<JsValue>(0)?;
        neon_serde::from_value(&mut cx, path).unwrap()
    };

    let data = std::fs::read(path).unwrap();
    let inner = Parameters::read(&mut data.as_slice(), true, true).unwrap();

    Ok(cx.boxed(Arc::new(Params { inner })))
}

impl Finalize for Params {}
