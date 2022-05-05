//! Test suite for the Web and headless browsers.

#![cfg(target_arch = "wasm32")]

extern crate libzkbob_rs_wasm;
extern crate wasm_bindgen_test;

use fawkes_crypto::ff_uint::Num;
use libzeropool::native::params::PoolBN256;
use libzeropool::POOL_PARAMS;
use libzkbob_rs::sparse_array::SparseArray;
use libzkbob_rs_wasm::{TxType, UserAccount, UserState};
use serde_json::{json, Value as JsonValue};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

// TODO: More extensive tests

const SEED: &[u8] = &[1, 2, 3];

async fn init_acc() -> UserAccount {
    let state = UserState::init("test".to_owned()).await;
    UserAccount::from_seed(SEED, state).unwrap()
}

// #[wasm_bindgen_test]
// fn test_account_from_seed() {
//     let sk = derive_sk(SEED);
//     let _keys = Keys::derive(&sk).unwrap();

//     assert!(true)
// }

#[wasm_bindgen_test]
async fn test_sparse_array_iter_slice() {
    use kvdb::KeyValueDB;
    let a = SparseArray::new_web("test-test").await;
    a.set(1, &1u32);
    a.set(3, &2);
    a.set(412345, &3);

    assert_eq!(a.db.iter(0).count(), 3, "inner");
    assert_eq!(a.iter().collect::<Vec<_>>().len(), 3, "iter");

    assert_eq!(a.iter_slice(0..=412345).count(), 3, "all");
    assert_eq!(a.iter_slice(1..=412345).count(), 3, "from 1");
    assert_eq!(a.iter_slice(2..=412345).count(), 2, "from 2");
    assert_eq!(a.iter_slice(2..=412344).count(), 1, "from 2 except last");
}

// #[wasm_bindgen_test]
// async fn account_create_tx() {
//     let mut acc = init_acc().await;

//     let tx: JsonValue = serde_wasm_bindgen::from_value(
//         JsFuture::from(acc.create_tx(
//             TxType::Deposit,
//             JsValue::from_serde("1").unwrap().unchecked_into(),
//             None,
//             None,
//         ))
//         .await
//         .unwrap(),
//     )
//     .unwrap();

//     let account = serde_wasm_bindgen::to_value(&tx["secret"]["tx"]["output"][0])
//         .unwrap()
//         .unchecked_into();

//     acc.add_account(0, account);

//     // let addr = acc.generate_address();

//     // let tx = JsFuture::from(acc.create_tx(
//     //     TxType::Withdraw,
//     //     JsValue::from_serde("1")
//     //         .unwrap()
//     //         .unchecked_into(),
//     //     None,
//     //     None,
//     // )).await.unwrap();

//     // let tx: JsonValue = serde_wasm_bindgen::from_value(tx).unwrap();

//     println!("{}", tx["test"]);
// }

// #[wasm_bindgen_test]
// async fn account_total_balance() {
//     let acc = init_acc().await;

//     assert_eq!(acc.total_balance(), "0");
// }
