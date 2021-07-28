use libzeropool::{
    fawkes_crypto::ff_uint::{Num, NumRepr, Uint},
    native::key::{derive_key_a, derive_key_eta},
    POOL_PARAMS,
};
use wasm_bindgen::{prelude::*, JsValue};

use crate::types::{Fr, Fs};

#[wasm_bindgen(js_name = deriveSecretKey)]
pub fn derive_sk(seed: &[u8]) -> Vec<u8> {
    let sk = Num::<Fs>::from_uint_reduced(NumRepr(Uint::from_little_endian(seed)));
    sk.to_uint().0.to_little_endian()
}

pub struct Keys {
    pub sk: Num<Fs>,
    pub a: Num<Fr>,
    pub eta: Num<Fr>,
}

impl Keys {
    pub fn derive(sk: &[u8]) -> Result<Self, JsValue> {
        let num_sk = Num::<Fs>::from_uint(NumRepr(Uint::from_little_endian(sk)))
            .ok_or_else(|| js_err!("Invalid secret key"))?;
        let a = derive_key_a(num_sk, &*POOL_PARAMS).x;
        let eta = derive_key_eta(a, &*POOL_PARAMS);

        Ok(Keys { sk: num_sk, a, eta })
    }
}
