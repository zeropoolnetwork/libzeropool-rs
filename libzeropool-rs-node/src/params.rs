use std::cell::RefCell;

use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use neon::prelude::*;

use crate::Engine;

pub type BoxedParams = JsBox<RefCell<Params>>;

pub struct Params {
    pub inner: Parameters<Engine>,
}

pub fn from_binary(mut cx: FunctionContext) -> JsResult<BoxedParams> {
    let input = cx.argument::<JsBuffer>(0)?;

    let inner = cx.borrow(&input, |data| {
        let mut data = data.as_slice();
        Parameters::read(&mut data, true, true).unwrap()
    });

    Ok(cx.boxed(RefCell::new(Params { inner })))
}

impl Finalize for Params {}
