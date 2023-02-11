use std::str::FromStr;

use libzeropool_rs::{
    client::TransactionData,
    delegated_deposit::{DelegatedDepositData, MemoDelegatedDeposit},
    libzeropool::{
        constants,
        fawkes_crypto::{core::sizedvec::SizedVec, ff_uint::Num, native::poseidon::MerkleProof},
        native::{
            account::Account,
            boundednum::BoundedNum,
            delegated_deposit::{
                DelegatedDeposit, DelegatedDepositBatchPub, DelegatedDepositBatchSec,
            },
            note::Note,
            tx::{out_commitment_hash, TransferPub, TransferSec, Tx},
        },
        POOL_PARAMS,
    },
    utils::{zero_account, zero_note},
};
use neon::prelude::*;

use crate::Fr;

trait ToJs {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue>;
}

trait FromJs {
    fn from_js<'a, C: Context<'a>>(cx: &mut C, value: Handle<'a, JsValue>) -> Self;
}

fn string_or_num_to_u64<'a, C: Context<'a>>(cx: &mut C, value: Handle<'a, JsValue>) -> u64 {
    if value.is_a::<JsString, _>(cx) {
        let value = value.downcast::<JsString, _>(cx).unwrap().value(cx);
        u64::from_str(&value).unwrap()
    } else {
        value.downcast::<JsNumber, _>(cx).unwrap().value(cx) as u64
    }
}

fn string_or_num_to_num<'a, C: Context<'a>>(cx: &mut C, value: Handle<'a, JsValue>) -> Num<Fr> {
    if value.is_a::<JsString, _>(cx) {
        let value = value.downcast::<JsString, _>(cx).unwrap().value(cx);
        Num::from_str(&value).unwrap()
    } else {
        let value = value.downcast::<JsNumber, _>(cx).unwrap().value(cx) as u64;
        Num::from(value)
    }
}

impl FromJs for MemoDelegatedDeposit<Fr> {
    fn from_js<'a, C: Context<'a>>(cx: &mut C, value: Handle<'a, JsValue>) -> Self {
        let obj = value.downcast::<JsObject, _>(cx).unwrap();

        let id_js = obj.get_value(cx, "id").unwrap();
        let id = string_or_num_to_u64(cx, id_js);

        let receiver_d_js = obj.get_value(cx, "receiver_d").unwrap();
        let receiver_d = string_or_num_to_num(cx, receiver_d_js);

        let receiver_p = obj.get_value(cx, "receiver_p").unwrap();
        let receiver_p = string_or_num_to_num(cx, receiver_p);

        let denominated_amount_js = obj.get_value(cx, "denominated_amount").unwrap();
        let denominated_amount = string_or_num_to_u64(cx, denominated_amount_js);

        MemoDelegatedDeposit {
            id,
            receiver_d: BoundedNum::new(receiver_d),
            receiver_p,
            denominated_amount,
        }
    }
}

impl ToJs for bool {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        Ok(cx.boolean(*self).upcast())
    }
}

impl<T: ToJs> ToJs for &[T] {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let arr = JsArray::new(cx, self.len() as u32);
        for (i, item) in self.iter().enumerate() {
            let item = item.to_js(cx)?;
            arr.set(cx, i as u32, item)?;
        }

        Ok(arr.upcast())
    }
}

impl ToJs for DelegatedDepositData<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let public = self.public.to_js(cx)?;
        obj.set(cx, "public", public)?;

        let secret = self.secret.to_js(cx)?;
        obj.set(cx, "secret", secret)?;

        let memo = JsBuffer::external(cx, self.memo.clone());
        obj.set(cx, "memo", memo)?;

        Ok(obj.upcast())
    }
}

impl ToJs for DelegatedDepositBatchPub<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let keccak_sum = cx.string(self.keccak_sum.to_string());
        obj.set(cx, "keccak_sum", keccak_sum)?;

        Ok(obj.upcast())
    }
}

impl ToJs for DelegatedDepositBatchSec<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let deposits = self.deposits.as_slice().to_js(cx)?;
        obj.set(cx, "deposits", deposits)?;

        Ok(obj.upcast())
    }
}

impl ToJs for DelegatedDeposit<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let d = cx.string(self.d.to_num().to_string());
        obj.set(cx, "d", d)?;
        let p_d = cx.string(self.p_d.to_string());
        obj.set(cx, "p_d", p_d)?;
        let b = cx.string(self.b.to_num().to_string());
        obj.set(cx, "b", b)?;

        Ok(obj.upcast())
    }
}

impl ToJs for TransactionData<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let public = self.public.to_js(cx)?;
        obj.set(cx, "public", public)?;

        let secret = self.secret.to_js(cx)?;
        obj.set(cx, "secret", secret)?;

        let ciphertext = JsBuffer::external(cx, self.ciphertext.clone());
        obj.set(cx, "ciphertext", ciphertext)?;

        let memo = JsBuffer::external(cx, self.memo.clone());
        obj.set(cx, "memo", memo)?;

        let commitment_root = cx.string(self.commitment_root.to_string());
        obj.set(cx, "commitment_root", commitment_root)?;

        let out_hashes = self.out_hashes.as_slice().to_js(cx)?;
        obj.set(cx, "out_hashes", out_hashes)?;

        Ok(obj.upcast())
    }
}

impl ToJs for TransferPub<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
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

        Ok(obj.upcast())
    }
}

impl ToJs for TransferSec<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let tx = self.tx.to_js(cx)?;
        obj.set(cx, "tx", tx)?;

        let in_proof = cx.empty_object();
        let in_proof_account = self.in_proof.0.to_js(cx)?;
        in_proof.set(cx, "account", in_proof_account)?;
        let in_proof_notes = self.in_proof.1.as_slice().to_js(cx)?;
        in_proof.set(cx, "notes", in_proof_notes)?;
        obj.set(cx, "in_proof", in_proof)?;

        let eddsa_s = cx.string(self.eddsa_s.to_string());
        obj.set(cx, "eddsa_s", eddsa_s)?;
        let eddsa_r = cx.string(self.eddsa_r.to_string());
        obj.set(cx, "eddsa_r", eddsa_r)?;
        let eddsa_a = cx.string(self.eddsa_a.to_string());
        obj.set(cx, "eddsa_a", eddsa_a)?;

        Ok(obj.upcast())
    }
}

impl<const L: usize> ToJs for MerkleProof<Fr, L> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let sibling = cx.empty_array();
        for (i, sib) in self.sibling.iter().enumerate() {
            let sib = cx.string(sib.to_string());
            sibling.set(cx, i as u32, sib)?;
        }
        obj.set(cx, "sibling", sibling)?;

        let path = self.path.as_slice().to_js(cx)?;
        obj.set(cx, "path", path)?;

        Ok(obj.upcast())
    }
}

impl ToJs for Tx<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        // input
        let input = cx.empty_object();
        let account = self.input.0.to_js(cx)?;
        input.set(cx, "account", account)?;
        let notes = self.input.1.as_slice().to_js(cx)?;
        input.set(cx, "notes", notes)?;
        obj.set(cx, "input", input)?;

        // output
        let output = cx.empty_object();
        let account = self.output.0.to_js(cx)?;
        output.set(cx, "account", account)?;
        let notes = self.output.1.as_slice().to_js(cx)?;
        output.set(cx, "notes", notes)?;
        obj.set(cx, "output", output)?;

        Ok(obj.upcast())
    }
}

impl ToJs for Account<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
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

        Ok(obj.upcast())
    }
}

impl ToJs for Note<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let obj = cx.empty_object();

        let d = cx.string(self.d.to_num().to_string());
        obj.set(cx, "d", d)?;
        let p_d = cx.string(self.p_d.to_string());
        obj.set(cx, "p_d", p_d)?;
        let b = cx.string(self.b.to_num().to_string());
        obj.set(cx, "b", b)?;
        let t = cx.string(self.t.to_num().to_string());
        obj.set(cx, "t", t)?;

        Ok(obj.upcast())
    }
}

impl ToJs for Num<Fr> {
    fn to_js<'a, C: Context<'a>>(&self, cx: &mut C) -> JsResult<'a, JsValue> {
        let num = self.to_string();
        let num = cx.string(num);

        Ok(num.upcast())
    }
}

pub fn create_delegated_deposit_tx_async(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let deposits_js = cx.argument::<JsArray>(0)?.to_vec(&mut cx)?;
    let deposits: Vec<_> = deposits_js
        .into_iter()
        .map(|obj| MemoDelegatedDeposit::from_js(&mut cx, obj))
        .collect();

    let channel = cx.channel();
    let (deferred, promise) = cx.promise();

    rayon::spawn(move || {
        let tx = DelegatedDepositData::create(&deposits, &*POOL_PARAMS)
            .expect("Failed to create delegated deposit tx");

        deferred.settle_with(&channel, move |mut cx| {
            tx.to_js(&mut cx)
                .or_else(|err| cx.throw_error(err.to_string()))
        });
    });

    Ok(promise)
}

pub fn delegated_deposits_to_commitment(mut cx: FunctionContext) -> JsResult<JsString> {
    let deposits_js = cx.argument::<JsArray>(0)?.to_vec(&mut cx)?;
    let deposits: Vec<_> = deposits_js
        .into_iter()
        .map(|obj| MemoDelegatedDeposit::from_js(&mut cx, obj))
        .collect();

    let note_hashes = deposits
        .into_iter()
        .map(|d| d.to_delegated_deposit().to_note().hash(&*POOL_PARAMS));

    let out_hashes: SizedVec<Num<Fr>, { constants::OUT + 1 }> =
        std::iter::once(zero_account().hash(&*POOL_PARAMS))
            .chain(note_hashes)
            .chain(std::iter::repeat(zero_note().hash(&*POOL_PARAMS)))
            .take(constants::OUT + 1)
            .collect();

    let out_commitment_hash = out_commitment_hash(out_hashes.as_slice(), &*POOL_PARAMS);
    let res = out_commitment_hash.to_string();

    Ok(cx.string(res))
}
