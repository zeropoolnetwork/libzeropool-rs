use std::str::FromStr;

use wasm_bindgen::prelude::*;
use libzeropool::{fawkes_crypto::{
      ff_uint::Num,
  }, native::tx::out_commitment_hash};
use libzkbob_rs::{
  libzeropool::fawkes_crypto::borsh::{BorshSerialize, BorshDeserialize},
  libzeropool::POOL_PARAMS
};
use crate::{Fr};
use crate::ts_types::RawHashes;


#[wasm_bindgen]
pub struct Helpers {
}

#[wasm_bindgen]
impl Helpers {
    #[wasm_bindgen(js_name = "strToNum")]
    pub fn str_to_num(num_str: String) -> Vec<u8> {
      let num: Num<Fr> = Num::from_str(num_str.as_str()).unwrap();
  
      let mut vec = vec![];
      num.serialize(&mut vec).unwrap();

      vec
    }

    #[wasm_bindgen(js_name = "numToStr")]
    pub fn num_to_str(num: Vec<u8>) -> String {
      let num: Num<Fr> = Num::try_from_slice(num.as_slice()).unwrap();
      num.to_string()
    }

    #[wasm_bindgen(js_name = "outCommitmentHash")]
    pub fn out_commitment(hashes: RawHashes) -> String {
      let hashes = serde_wasm_bindgen::from_value::<Vec<Vec<u8>>>(hashes.into()).unwrap();
      let hashes: Vec<Num<Fr>> = hashes
        .iter()
        .map(|h| Num::try_from_slice(h).unwrap())
        .collect();
      let commitment = out_commitment_hash(&hashes, &*POOL_PARAMS);

      commitment.to_string()
    }
}
