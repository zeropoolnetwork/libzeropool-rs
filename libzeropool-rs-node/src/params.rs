use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
use neon::prelude::*;

use crate::Engine;

pub struct Params {
    pub inner: Parameters<Engine>,
}

pub fn from_binary(mut cx: FunctionContext) -> JsResult<Params> {
    let mut input = cx.argument::<JsBuffer>(0)?.try_borrow().as_slice::<u8>();
    let inner = Parameters::read(&mut input, true, true).map_err(|err| js_err!("{}", err))?;

    Ok((Params { inner }).upcast())
}

declare_types! {
    pub class JsParams for Params {}
}

register_module!(mut m, {
    m.export_function("fromBinary", from_binary)?;
    m.export_class::<JsParams>("Params")?;
    Ok(())
});
