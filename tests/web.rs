//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate libzeropool_wasm;
extern crate wasm_bindgen_test;

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn derive() {
    let result = libzeropool_wasm::derive_address(b"12300000000000000000000000000000");
    assert!(result.is_ok());
}

#[wasm_bindgen_test]
fn parse() {
    let addr = libzeropool_wasm::derive_address(b"12300000000000000000000000000000").unwrap();
    libzeropool_wasm::parse_address(addr).unwrap();
}
