use libzeropool::{
    fawkes_crypto::borsh::BorshDeserialize,
    fawkes_crypto::ff_uint::{Num, NumRepr, Uint},
    native::key::{derive_key_a, derive_key_eta},
    native::params::{PoolBN256, PoolParams},
};
use wasm_bindgen::{prelude::*, JsValue};

#[wasm_bindgen(js_name = deriveSecretKey)]
pub fn derive_sk(seed: &[u8]) -> Vec<u8> {
    let sk = Num::<<PoolBN256 as PoolParams>::Fr>::from_uint_reduced(NumRepr(
        Uint::from_big_endian(seed),
    ));
    sk.to_uint().0.to_big_endian()
}

pub struct Keys<P: PoolParams> {
    pub sk: Num<P::Fs>,
    pub a: Num<P::Fr>,
    pub eta: Num<P::Fr>,
}

impl<P: PoolParams> Keys<P> {
    pub fn derive(sk: &[u8], params: &P) -> Result<Self, JsValue> {
        let num_sk = Num::try_from_slice(sk).map_err(|err| JsValue::from(err.to_string()))?;
        let a = derive_key_a(num_sk, params).x;
        let eta = derive_key_eta(a, params);

        Ok(Keys { sk: num_sk, a, eta })
    }
}
