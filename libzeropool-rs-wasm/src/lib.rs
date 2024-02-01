use std::{convert::TryInto, str::FromStr};

#[cfg(feature = "groth16")]
use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::{
    engines::Bn256, prover::Proof as Groth16Proof,
};
#[cfg(feature = "plonk")]
use libzeropool_rs::libzeropool::fawkes_crypto::backend::plonk::{
    engines::Bn256, prover::Proof as PlonkProof,
};
use libzeropool_rs::{
    address::{format_address, parse_address},
    libzeropool::{
        constants,
        fawkes_crypto::ff_uint::Num,
        native::{
            boundednum::BoundedNum,
            params::{PoolBN256, PoolParams as PoolParamsTrait},
            tx::parse_delta,
        },
        POOL_PARAMS,
    },
};
use serde::Serialize;
use wasm_bindgen::{prelude::*, JsCast};
#[cfg(feature = "multicore")]
pub use wasm_bindgen_rayon::init_thread_pool;

pub use crate::{
    client::*,
    proof::*,
    state::{Transaction, UserState},
    ts_types::*,
};

#[macro_use]
mod utils;
mod client;
mod database;
mod helpers;
mod keys;
mod params;
mod proof;
mod state;
mod ts_types;

pub type PoolParams = PoolBN256;
pub type Fr = <PoolParams as PoolParamsTrait>::Fr;
pub type Fs = <PoolParams as PoolParamsTrait>::Fs;
pub type Engine = Bn256;

#[cfg(feature = "groth16")]
pub type SnarkProof = Groth16Proof<Engine>;
#[cfg(feature = "plonk")]
pub type SnarkProof = PlonkProof;

lazy_static::lazy_static! {
    static ref CONSTANTS: SerConstants = SerConstants::new();
}

#[allow(non_snake_case)]
#[derive(Clone, Serialize)]
pub struct SerConstants {
    pub IN: usize,
    pub OUT: usize,
    pub OUTLOG: usize,
    pub HEIGHT: usize,
}

impl SerConstants {
    fn new() -> Self {
        SerConstants {
            IN: constants::IN,
            OUT: constants::OUT,
            OUTLOG: constants::OUTPLUSONELOG,
            HEIGHT: constants::HEIGHT,
        }
    }
}

#[wasm_bindgen(js_name = "getConstants")]
pub fn get_constants() -> Constants {
    serde_wasm_bindgen::to_value(&*CONSTANTS)
        .unwrap()
        .unchecked_into::<Constants>()
}

#[wasm_bindgen(js_name = "validateAddress")]
pub fn validate_address(address: &str) -> bool {
    parse_address::<PoolParams>(address).is_ok()
}

#[wasm_bindgen(js_name = "assembleAddress")]
pub fn assemble_address(d: &str, p_d: &str) -> String {
    let d = Num::from_str(d).unwrap();
    let d = BoundedNum::new(d);
    let p_d = Num::from_str(p_d).unwrap();

    format_address::<PoolParams>(d, p_d)
}

#[wasm_bindgen(js_name = "parseAddress")]
pub fn parse_address_(address: &str) -> IAddressComponents {
    let (d, p_d) = parse_address::<PoolParams>(address).unwrap();

    #[derive(Serialize)]
    struct Address {
        d: String,
        p_d: String,
    }

    let address = Address {
        d: d.to_num().to_string(),
        p_d: p_d.to_string(),
    };

    serde_wasm_bindgen::to_value(&address)
        .unwrap()
        .unchecked_into::<IAddressComponents>()
}

#[wasm_bindgen(js_name = "parseDelta")]
pub fn parse_delta_(delta: &str) -> IParsedDelta {
    let delta = Num::<Fr>::from_str(delta).unwrap();

    let (token_amount, energy_amount, transfer_index, pool_id) = parse_delta(delta);

    let token_amount: i64 = token_amount.try_into().unwrap();
    let energy_amount: i64 = energy_amount.try_into().unwrap();

    let parsed_delta = ParsedDelta {
        v: token_amount.to_string(),
        e: energy_amount.to_string(),
        index: transfer_index.to_string(),
        pool_id: pool_id.to_string(),
    };

    serde_wasm_bindgen::to_value(&parsed_delta)
        .unwrap()
        .unchecked_into::<IParsedDelta>()
}
