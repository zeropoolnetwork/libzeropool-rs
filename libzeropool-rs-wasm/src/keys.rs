use libzeropool_rs::{
    keys::reduce_sk as reduce_sk_native, libzeropool::fawkes_crypto::ff_uint::Uint,
};
use wasm_bindgen::prelude::*;

use crate::Fs;

#[wasm_bindgen(js_name = reduceSpendingKey)]
pub fn reduce_sk(seed: &[u8]) -> Vec<u8> {
    reduce_sk_native::<Fs>(seed).to_uint().0.to_little_endian()
}
