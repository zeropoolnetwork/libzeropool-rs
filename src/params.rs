use fawkes_crypto::backend::bellman_groth16::Parameters;
use wasm_bindgen::prelude::*;

use crate::Engine;

#[wasm_bindgen]
pub struct Params {
    inner: Parameters<Engine>,
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
    #[wasm_bindgen(js_name = "loadFromBinary")]
    pub fn load_from_binary(input: &[u8]) -> Params {
        todo!()
    }
}
