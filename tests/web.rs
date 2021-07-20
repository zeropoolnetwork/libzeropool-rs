//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate libzeropool_wasm;
extern crate wasm_bindgen_test;

use fawkes_crypto::ff_uint::Num;
use libzeropool::native::params::PoolBN256;
use libzeropool::POOL_PARAMS;
use libzeropool_wasm::{derive_sk, Keys, State, UserAccount};
use serde_json::json;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// TODO: More extensive tests

const SEED: &[u8] = &[1, 2, 3];

#[wasm_bindgen_test]
fn test_account_from_seed() {
    let sk = derive_sk(SEED);
    let _keys = Keys::derive(&sk, &*POOL_PARAMS).unwrap();

    assert!(true)
}

#[wasm_bindgen_test]
async fn account_derive_new_address() {
    let state = State::init("test".to_owned()).await;
    let acc = UserAccount::from_seed(SEED, state).unwrap();
    let _result = acc.generate_address();
}

#[wasm_bindgen_test]
async fn parse_address() {
    let state = State::init("test".to_owned()).await;
    let acc = UserAccount::from_seed(SEED, state).unwrap();
    let addr = acc.generate_address();
    let _ = libzeropool_wasm::parse_address::<PoolBN256>(&addr).unwrap();
}

#[wasm_bindgen_test]
async fn make_tx() {
    let state = State::init("test".to_owned()).await;
    let acc = UserAccount::from_seed(SEED, state).unwrap();
    let addr = acc.generate_address();
    let _tx = acc.make_tx(
        JsValue::from_serde(&json!([{ "to": addr, "amount": "0" }]))
            .unwrap()
            .unchecked_into(),
        None,
    );
}
