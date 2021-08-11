use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use neon::prelude::*;

use crate::Engine;

pub struct Params {
    pub inner: Parameters<Engine>,
}

pub fn from_binary(mut cx: FunctionContext) -> JsResult<JsBox<Params>> {
    let input = cx.argument::<JsBuffer>(0)?;
    let guard = cx.lock();
    let mut input = input.borrow(&guard).as_slice::<u8>();
    let inner = Parameters::read(&mut input, true, true).unwrap();

    Ok(cx.boxed(Params { inner }))
}

impl Finalize for Params {}
