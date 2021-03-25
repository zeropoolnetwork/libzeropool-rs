use fawkes_crypto::{
    ff_uint::{Num, NumRepr, Uint},
    rand::Rng,
};
use libzeropool::{native::tx, POOL_PARAMS};
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

mod random;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen(js_name = deriveAddress)]
pub fn derive_address(dk: &[u8]) -> Result<String, JsValue> {
    let mut rng = random::CustomRng;
    let d = rng.gen();
    let dk = Num::from_uint_reduced(NumRepr(Uint::from_big_endian(dk)));
    let pk_d = tx::derive_key_pk_d(d, dk, &*POOL_PARAMS);
    let mut buf: Vec<u8> = Vec::with_capacity(48);

    buf.extend_from_slice(&d.to_uint().0.to_big_endian()[0..10]);
    buf.extend_from_slice(&pk_d.x.to_uint().0.to_big_endian()); // 32 bytes

    let mut hasher = Sha256::new();
    hasher.update(&buf);
    let hash = hasher.finalize();

    buf.extend_from_slice(&hash[0..4]);

    Ok(bs58::encode(buf).into_string())
}
