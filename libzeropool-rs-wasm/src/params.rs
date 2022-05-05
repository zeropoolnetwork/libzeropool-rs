use fawkes_crypto::backend::bellman_groth16::Parameters;
use wasm_bindgen::prelude::*;

use crate::Engine;

#[wasm_bindgen]
pub struct Params {
    #[wasm_bindgen(skip)]
    pub inner: Parameters<Engine>,
}

impl From<Parameters<Engine>> for Params {
    fn from(params: Parameters<Engine>) -> Self {
        Params { inner: params }
    }
}

impl From<Params> for Parameters<Engine> {
    fn from(params: Params) -> Self {
        params.inner
    }
}

#[wasm_bindgen]
impl Params {
    #[wasm_bindgen(js_name = "fromBinary")]
    pub fn from_binary(input: &[u8]) -> Result<Params, JsValue> {
        Self::from_binary_ext(input, true, true)
    }

    #[wasm_bindgen(js_name = "fromBinaryExtended")]
    pub fn from_binary_ext(input: &[u8], disallow_points_at_infinity: bool, checked: bool) -> Result<Params, JsValue> {
        let mut input = input;
        let inner = Parameters::read(&mut input, disallow_points_at_infinity, checked).map_err(|err| js_err!("{}", err))?;

        Ok(Params { inner })
    }
}
