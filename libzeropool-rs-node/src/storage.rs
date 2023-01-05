use libzeropool_rs::sparse_array::NativeSparseArray;
use neon::{prelude::*, types::buffer::TypedArray};

/// Stores encrypted accounts and notes.
pub struct TxStorage {
    inner: NativeSparseArray<Vec<u8>>,
}

pub type BoxedTxStorage = JsBox<TxStorage>;

impl Finalize for TxStorage {}

pub fn tx_storage_new(mut cx: FunctionContext) -> JsResult<BoxedTxStorage> {
    let path = {
        let path = cx.argument::<JsString>(0)?;
        path.value(&mut cx)
    };

    let inner = NativeSparseArray::new_native(&path).unwrap();

    Ok(cx.boxed(TxStorage { inner }))
}

pub fn tx_storage_add(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let buffer = cx.argument::<JsBuffer>(2)?;
    this.inner.set(index, &buffer.as_slice(&cx).to_vec());

    Ok(cx.undefined())
}

pub fn tx_storage_delete(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    this.inner.remove(index);

    Ok(cx.undefined())
}

pub fn tx_storage_get(mut cx: FunctionContext) -> JsResult<JsValue> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let result = if let Some(data) = this.inner.get(index) {
        JsBuffer::external(&mut cx, data).upcast()
    } else {
        cx.null().upcast()
    };

    Ok(result)
}

pub fn tx_storage_count(mut cx: FunctionContext) -> JsResult<JsValue> {
    let this = cx.argument::<BoxedTxStorage>(0)?;
    let len = JsNumber::new(&mut cx, this.inner.count() as f64).upcast();

    Ok(len)
}
