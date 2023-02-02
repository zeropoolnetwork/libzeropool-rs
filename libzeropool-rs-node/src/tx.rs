use std::str::FromStr;

use libzeropool_rs::{
    client::TransactionData,
    delegated_deposit::create_delegated_deposit_tx as create_delegated_deposit_tx_native,
    libzeropool::{
        fawkes_crypto::{ff_uint::Num, native::poseidon::MerkleProof},
        native::{
            account::Account,
            boundednum::BoundedNum,
            delegated_deposit::DelegatedDeposit,
            note::Note,
            tx::{TransferPub, TransferSec, Tx},
        },
        POOL_PARAMS,
    },
};
use neon::prelude::*;

use crate::Fr;

trait JsExt {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject>;
}

// TODO: Proper error handling
pub fn create_delegated_deposit_tx(mut cx: FunctionContext) -> JsResult<JsObject> {
    let deposits_js = cx.argument::<JsValue>(1)?;
    let deposits: Vec<DelegatedDeposit<Fr>> = neon_serde::from_value(&mut cx, deposits_js).unwrap();
    let root_js = cx.argument::<JsString>(2)?;
    let root = Num::from_str(&root_js.value(&mut cx)).unwrap();
    let keys_js = cx.argument::<JsValue>(3)?;
    let keys = neon_serde::from_value(&mut cx, keys_js).unwrap();
    let pool_id_js = cx.argument::<JsString>(4)?;
    let pool_id = Num::from_str(&pool_id_js.value(&mut cx)).unwrap();
    let tx = create_delegated_deposit_tx_native(
        &deposits,
        root,
        keys,
        BoundedNum::new(pool_id),
        &*POOL_PARAMS,
    )
    .expect("Failed to create delegated deposit tx");

    Ok(tx.to_object(&mut cx)?)
}

impl JsExt for TransactionData<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let public = self.public.to_object(cx)?;
        obj.set(cx, "public", public)?;

        let secret = self.secret.to_object(cx)?;
        obj.set(cx, "secret", secret)?;

        let ciphertext = JsBuffer::external(cx, self.ciphertext.clone());
        obj.set(cx, "ciphertext", ciphertext)?;

        let memo = JsBuffer::external(cx, self.memo.clone());
        obj.set(cx, "memo", memo)?;

        let commitment_root = cx.string(self.commitment_root.to_string());
        obj.set(cx, "commitment_root", commitment_root)?;

        let out_hashes = JsArray::new(cx, self.out_hashes.as_slice().len() as u32);
        for (i, hash) in self.out_hashes.as_slice().iter().enumerate() {
            let hash = cx.string(hash.to_string());
            out_hashes.set(cx, i as u32, hash)?;
        }
        obj.set(cx, "out_hashes", out_hashes)?;

        Ok(obj)
    }
}

impl JsExt for TransferPub<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let root = cx.string(self.root.to_string());
        obj.set(cx, "root", root)?;

        let nullifier = cx.string(self.nullifier.to_string());
        obj.set(cx, "nullifier", nullifier)?;

        let out_commit = cx.string(self.out_commit.to_string());
        obj.set(cx, "out_commit", out_commit)?;

        let delta = cx.string(self.delta.to_string());
        obj.set(cx, "delta", delta)?;

        let memo = cx.string(self.memo.to_string());
        obj.set(cx, "memo", memo)?;

        Ok(obj)
    }
}

impl JsExt for TransferSec<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let tx = self.tx.to_object(cx)?;
        obj.set(cx, "tx", tx)?;

        let in_proof = cx.empty_object();
        let in_proof_account = self.in_proof.0.to_object(cx)?;
        in_proof.set(cx, "account", in_proof_account)?;
        let in_proof_notes = cx.empty_array();
        for (i, note) in self.in_proof.1.iter().enumerate() {
            let note = note.to_object(cx)?;
            in_proof_notes.set(cx, i as u32, note)?;
        }
        in_proof.set(cx, "notes", in_proof_notes)?;
        obj.set(cx, "in_proof", in_proof)?;

        let eddsa_s = cx.string(self.eddsa_s.to_string());
        obj.set(cx, "eddsa_s", eddsa_s)?;
        let eddsa_r = cx.string(self.eddsa_r.to_string());
        obj.set(cx, "eddsa_r", eddsa_r)?;
        let eddsa_a = cx.string(self.eddsa_a.to_string());
        obj.set(cx, "eddsa_a", eddsa_a)?;

        Ok(obj)
    }
}

impl<const L: usize> JsExt for MerkleProof<Fr, L> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let sibling = cx.empty_array();
        for (i, sib) in self.sibling.iter().enumerate() {
            let sib = cx.string(sib.to_string());
            sibling.set(cx, i as u32, sib)?;
        }
        obj.set(cx, "sibling", sibling)?;

        let path = cx.empty_array();
        for (i, p) in self.path.iter().enumerate() {
            let p = cx.boolean(*p);
            path.set(cx, i as u32, p)?;
        }
        obj.set(cx, "path", path)?;

        Ok(obj)
    }
}

impl JsExt for Tx<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        // input
        let input = cx.empty_object();
        let account = self.input.0.to_object(cx)?;
        input.set(cx, "account", account)?;
        let notes = cx.empty_array();
        for (i, note) in self.input.1.iter().enumerate() {
            let note = note.to_object(cx)?;
            notes.set(cx, i as u32, note)?;
        }
        input.set(cx, "notes", notes)?;
        obj.set(cx, "input", input)?;

        // output
        let output = cx.empty_object();
        let account = self.output.0.to_object(cx)?;
        output.set(cx, "account", account)?;
        let notes = cx.empty_array();
        for (i, note) in self.output.1.iter().enumerate() {
            let note = note.to_object(cx)?;
            notes.set(cx, i as u32, note)?;
        }
        output.set(cx, "notes", notes)?;
        obj.set(cx, "output", output)?;

        Ok(obj)
    }
}

impl JsExt for Account<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let d = cx.string(self.d.to_num().to_string());
        obj.set(cx, "d", d)?;
        let p_d = cx.string(self.p_d.to_string());
        obj.set(cx, "p_d", p_d)?;
        let i = cx.string(self.i.to_num().to_string());
        obj.set(cx, "i", i)?;
        let b = cx.string(self.b.to_num().to_string());
        obj.set(cx, "b", b)?;
        let e = cx.string(self.e.to_num().to_string());
        obj.set(cx, "e", e)?;

        Ok(obj)
    }
}

impl JsExt for Note<Fr> {
    fn to_object<'a>(&self, cx: &mut FunctionContext<'a>) -> JsResult<'a, JsObject> {
        let obj = cx.empty_object();

        let d = cx.string(self.d.to_num().to_string());
        obj.set(cx, "d", d)?;
        let p_d = cx.string(self.p_d.to_string());
        obj.set(cx, "p_d", p_d)?;
        let b = cx.string(self.b.to_num().to_string());
        obj.set(cx, "b", b)?;
        let t = cx.string(self.t.to_num().to_string());
        obj.set(cx, "t", t)?;

        Ok(obj)
    }
}
