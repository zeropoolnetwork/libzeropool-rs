use libzeropool::{
    circuit::{tree::tree_update, tx::c_transfer},
    fawkes_crypto::{
        backend::bellman_groth16::{
            prover::{prove, Proof as SnarkProof},
            verifier::{verify, VK},
        },
        ff_uint::Num,
    },
    native::{
        tree::{TreePub as NativeTreePub, TreeSec as NativeTreeSec},
        tx::{TransferPub as NativeTransferPub, TransferSec as NativeTransferSec},
    },
    POOL_PARAMS,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::{prelude::*, JsCast};

use crate::{params::Params, ts_types, Engine, Fr};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct Proof {
    inputs: Vec<Num<Fr>>,
    proof: SnarkProof<Engine>,
}

#[wasm_bindgen]
impl Proof {
    #[wasm_bindgen(js_name = "verify")]
    pub fn verify(
        vk: ts_types::VK,
        inputs: ts_types::SnarkInputs,
        proof: ts_types::SnarkProof,
    ) -> Result<bool, JsValue> {
        let vk: VK<Engine> = serde_wasm_bindgen::from_value(vk.unchecked_into::<JsValue>())?;
        let proof: SnarkProof<Engine> =
            serde_wasm_bindgen::from_value(proof.unchecked_into::<JsValue>())?;
        let inputs: Vec<Num<Fr>> =
            serde_wasm_bindgen::from_value(inputs.unchecked_into::<JsValue>())?;

        Ok(verify(&vk, &proof, &inputs))
    }

    #[wasm_bindgen(js_name = "tx")]
    pub fn tx(
        params: &Params,
        transfer_pub: ts_types::TransferPub,
        transfer_sec: ts_types::TransferSec,
    ) -> Result<crate::ts_types::Proof, JsValue> {
        let params = &params.inner;

        let public: NativeTransferPub<_> =
            serde_wasm_bindgen::from_value(transfer_pub.unchecked_into::<JsValue>())?;
        let secret: NativeTransferSec<_> =
            serde_wasm_bindgen::from_value(transfer_sec.unchecked_into::<JsValue>())?;

        let circuit = |public, secret| {
            c_transfer(&public, &secret, &*POOL_PARAMS);
        };

        let (inputs, snark_proof) = prove(params, &public, &secret, circuit);

        let proof = Proof {
            inputs,
            proof: snark_proof,
        };

        Ok(serde_wasm_bindgen::to_value(&proof)?.unchecked_into::<crate::ts_types::Proof>())
    }

    #[wasm_bindgen(js_name = "tree")]
    pub fn tree(
        params: &Params,
        tree_pub: ts_types::TreePub,
        tree_sec: ts_types::TreeSec,
    ) -> Result<crate::ts_types::Proof, JsValue> {
        let params = &params.inner;

        let public: NativeTreePub<_> =
            serde_wasm_bindgen::from_value(tree_pub.unchecked_into::<JsValue>())?;
        let secret: NativeTreeSec<_> =
            serde_wasm_bindgen::from_value(tree_sec.unchecked_into::<JsValue>())?;

        let circuit = |public, secret| {
            tree_update(&public, &secret, &*POOL_PARAMS);
        };

        let (inputs, snark_proof) = prove(params, &public, &secret, circuit);

        let proof = Proof {
            inputs,
            proof: snark_proof,
        };

        Ok(serde_wasm_bindgen::to_value(&proof)?.unchecked_into::<crate::ts_types::Proof>())
    }
}
