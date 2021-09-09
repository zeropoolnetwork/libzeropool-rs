use std::cell::RefCell;

use libzeropool_rs::libzeropool::fawkes_crypto::borsh::BorshDeserialize;
use libzeropool_rs::libzeropool::fawkes_crypto::ff_uint::Num;
use libzeropool_rs::libzeropool::{POOL_PARAMS, constants::{HEIGHT, OUTLOG}};
use libzeropool_rs::merkle::NativeMerkleTree;
use neon::prelude::*;

use crate::PoolParams;

pub struct MerkleTree {
    inner: NativeMerkleTree<PoolParams>,
}

pub type BoxedMerkleTree = JsBox<RefCell<MerkleTree>>;

impl Finalize for MerkleTree {}

pub fn merkle_new(mut cx: FunctionContext) -> JsResult<BoxedMerkleTree> {
    let path_js = cx.argument::<JsString>(0)?;
    let path = path_js.value(&mut cx);
    let inner =
        NativeMerkleTree::new_native(&Default::default(), &path, POOL_PARAMS.clone()).unwrap();

    Ok(cx.boxed(RefCell::new(MerkleTree { inner })))
}

pub fn merkle_add_hash(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let hash = {
        let buffer = cx.argument::<JsBuffer>(2)?;
        cx.borrow(&buffer, |data| {
            Num::try_from_slice(data.as_slice()).unwrap()
        })
    };

    tree.borrow_mut().inner.add_hash(index, hash, false);

    Ok(cx.undefined())
}

pub fn merkle_append_hash(mut cx: FunctionContext) -> JsResult<JsNumber> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let hash = {
        let buffer = cx.argument::<JsBuffer>(1)?;
        cx.borrow(&buffer, |data| {
            Num::try_from_slice(data.as_slice()).unwrap()
        })
    };

    let index = tree.borrow_mut().inner.append_hash(hash, false) as f64;

    Ok(cx.number(index))
}

pub fn merkle_get_leaf_proof(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let proof = tree
        .borrow()
        .inner
        .get_leaf_proof(index)
        .map(|proof| neon_serde::to_value(&mut cx, &proof).unwrap())
        .unwrap();

    Ok(proof)
}

pub fn merkle_get_commitment_proof(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let index: u64 = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let proof = tree
        .borrow()
        .inner
        .get_proof_unchecked::<{ HEIGHT - OUTLOG }>(index);

    let result = neon_serde::to_value(&mut cx, &proof).unwrap();

    Ok(result)
}

pub fn merkle_get_root(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let root = tree.borrow().inner.get_root();

    let result = neon_serde::to_value(&mut cx, &root).unwrap();

    Ok(result)
}

pub fn merkle_get_node(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;
    let height: u32 = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u32
    };
    let index: u64 = {
        let num = cx.argument::<JsNumber>(2)?;
        num.value(&mut cx) as u64
    };

    let hash = tree.borrow().inner.get(height, index);

    let result = neon_serde::to_value(&mut cx, &hash).unwrap();

    Ok(result)
}

pub fn merkle_get_next_index(mut cx: FunctionContext) -> JsResult<JsValue> {
    let tree = cx.argument::<BoxedMerkleTree>(0)?;

    let root = tree.borrow().inner.next_index();

    let result = neon_serde::to_value(&mut cx, &root).unwrap();

    Ok(result)
}
