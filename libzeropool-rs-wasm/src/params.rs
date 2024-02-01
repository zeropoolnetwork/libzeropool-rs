use libzeropool_rs::libzeropool::circuit::tx::c_transfer;
#[cfg(feature = "groth16")]
use libzeropool_rs::libzeropool::fawkes_crypto::backend::bellman_groth16::Parameters;
#[cfg(feature = "plonk")]
use libzeropool_rs::libzeropool::fawkes_crypto::backend::plonk::{
    setup::{setup, ProvingKey},
    Parameters,
};
use wasm_bindgen::prelude::*;

use crate::{Engine, POOL_PARAMS};

#[wasm_bindgen]
pub struct Params {
    #[wasm_bindgen(skip)]
    pub inner: Parameters<Engine>,

    #[cfg(feature = "plonk")]
    #[wasm_bindgen(skip)]
    pub tx_pk: ProvingKey<Engine>,
}

#[cfg(feature = "groth16")]
impl From<Parameters<Engine>> for Params {
    fn from(params: Parameters<Engine>) -> Self {
        Params { inner: params }
    }
}

#[cfg(feature = "plonk")]
impl From<Parameters<Engine>> for Params {
    fn from(params: Parameters<Engine>) -> Self {
        let circuit = |public, secret| {
            c_transfer(&public, &secret, &*POOL_PARAMS);
        };

        let (_, tx_pk) = setup(&params, circuit);

        Params {
            inner: params,
            tx_pk,
        }
    }
}

impl From<Params> for Parameters<Engine> {
    fn from(params: Params) -> Self {
        params.inner
    }
}

#[cfg(feature = "groth16")]
#[wasm_bindgen]
impl Params {
    #[wasm_bindgen(js_name = "fromBinary")]
    pub fn from_binary(input: &[u8]) -> Result<Params, JsValue> {
        Self::from_binary_ext(input, true, true)
    }

    #[wasm_bindgen(js_name = "fromBinaryExtended")]
    pub fn from_binary_ext(
        input: &[u8],
        disallow_points_at_infinity: bool,
        checked: bool,
    ) -> Result<Params, JsValue> {
        let mut input = input;

        let inner = Parameters::read(&mut input, disallow_points_at_infinity, checked)
            .map_err(|err| js_err!("{}", err))?;

        Ok(Params { inner })
    }
}

#[cfg(feature = "plonk")]
#[wasm_bindgen]
impl Params {
    #[wasm_bindgen(js_name = "fromBinaryWithPk")]
    pub fn from_binary_with_pk(params: &[u8], pk: &[u8]) -> Result<Params, JsValue> {
        let mut params_reader = params;
        let inner = Parameters::read(&mut params_reader).map_err(|err| js_err!("{}", err))?;
        let mut pk_reader = pk;
        let tx_pk = ProvingKey::<Engine>::read(&mut pk_reader).map_err(|err| js_err!("{}", err))?;

        Ok(Params { inner, tx_pk })
    }

    #[wasm_bindgen(js_name = "fromBinary")]
    pub fn from_binary(params: &[u8]) -> Result<Params, JsValue> {
        let mut params_reader = params;
        let inner = Parameters::read(&mut params_reader).map_err(|err| js_err!("{}", err))?;

        // let circuit = |public, secret| {
        //     c_transfer(&public, &secret, &*POOL_PARAMS);
        // };

        // let (_, tx_pk) = setup(&inner, circuit);

        // Ok(Params { inner, tx_pk })

        Ok(inner.into())
    }
}
