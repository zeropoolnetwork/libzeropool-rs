use libzeropool_rs::sparse_array::NativeSparseArray;
use neon::prelude::*;

use std::cell::RefCell;

/// Stores encrypted accounts and notes.
pub struct TxStorage {
    inner: NativeSparseArray<Vec<u8>>,
}

pub type BoxedTxStorage = JsBox<RefCell<TxStorage>>;

impl Finalize for TxStorage {}

pub fn tx_storage_new(mut cx: FunctionContext) -> JsResult<BoxedTxStorage> {
    let path = {
        let path = cx.argument::<JsString>(0)?;
        path.value(&mut cx)
    };

    let inner = NativeSparseArray::new_native(&Default::default(), &path).unwrap();

    Ok(cx.boxed(RefCell::new(TxStorage { inner })))
}

pub fn tx_storage_add(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let buffer = cx.argument::<JsBuffer>(2)?;
    cx.borrow(&buffer, |data| {
        this.borrow_mut()
            .inner
            .set(index, &data.as_slice().to_vec());
    });

    Ok(cx.undefined())
}

pub fn tx_storage_delete(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    this.borrow_mut().inner.remove(index);

    Ok(cx.undefined())
}

pub fn tx_storage_get(mut cx: FunctionContext) -> JsResult<JsValue> {
    let this = cx.argument::<BoxedTxStorage>(0)?;

    let index = {
        let num = cx.argument::<JsNumber>(1)?;
        num.value(&mut cx) as u64
    };

    let result = if let Some(data) = this.borrow().inner.get(index) {
        JsBuffer::external(&mut cx, data).upcast()
    } else {
        cx.null().upcast()
    };

    Ok(result)
}
