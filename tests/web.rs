//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate libzeropool_wasm;
extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn pass() {
    let result = libzeropool_wasm::derive_address("5".to_owned());
    assert!(result.is_ok());
}
