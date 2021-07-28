use libzeropool::{
    circuit::tree::tree_update,
    circuit::tx::c_transfer,
    fawkes_crypto::{
        backend::bellman_groth16::prover::{prove, Proof as SnarkProof},
        backend::bellman_groth16::Parameters,
        ff_uint::Num,
    },
    native::tx::{TransferPub as NativeTransferPub, TransferSec as NativeTransferSec},
    POOL_PARAMS,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};

use crate::{
    params::Params,
    types::{Engine, Fr, TransferPub, TransferSec},
};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Proof {
    inputs: Vec<Num<Fr>>,
    proof: SnarkProof<Engine>,
}

#[wasm_bindgen]
impl Proof {
    #[wasm_bindgen(js_name = "tx")]
    pub fn tx(
        params: Params,
        public_tx: TransferPub,
        secret_tx: TransferSec,
    ) -> Result<crate::types::Proof, JsValue> {
        use libzeropool::circuit::tx::c_transfer;

        let params: Parameters<Engine> = params.into();

        let public: NativeTransferPub<_> =
            serde_wasm_bindgen::from_value(public_tx.unchecked_into::<JsValue>())?;
        let secret: NativeTransferSec<_> =
            serde_wasm_bindgen::from_value(secret_tx.unchecked_into::<JsValue>())?;

        let circuit = |public, secret| {
            c_transfer(&public, &secret, &*POOL_PARAMS);
        };

        let (inputs, snark_proof) = prove(&params, &public, &secret, circuit);

        let proof = Proof {
            inputs,
            proof: snark_proof,
        };

        Ok(serde_wasm_bindgen::to_value(&proof)?.unchecked_into::<crate::types::Proof>())
    }

    #[wasm_bindgen(js_name = "tree")]
    pub fn tree() {}
}
