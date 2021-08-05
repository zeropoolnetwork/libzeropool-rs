use std::{convert::TryFrom, marker::PhantomData, ops::RangeInclusive};

use borsh::{BorshDeserialize, BorshSerialize};
use kvdb::{DBTransaction, KeyValueDB};

/// A persistent sparse array built on top of kvdb
pub struct SparseArray<D: KeyValueDB, T: BorshSerialize + BorshDeserialize> {
    db: D,
    _phantom: PhantomData<T>,
}

#[cfg(target_arch = "wasm32")]
impl<T> SparseArray<WebDatabase, T>
where
    T: BorshSerialize + BorshDeserialize,
{
    pub async fn new_web(name: &str) -> SparseArray<WebDatabase, T> {
        let db = WebDatabase::open(name.to_owned(), 1).await.unwrap();

        SparseArray {
            db,
            _phantom: Default::default(),
        }
    }
}

impl<D: KeyValueDB, T> SparseArray<D, T>
where
    D: KeyValueDB,
    T: BorshSerialize + BorshDeserialize + 'static,
{
    pub fn new(db: D) -> SparseArray<D, T> {
        SparseArray {
            db,
            _phantom: Default::default(),
        }
    }

    pub fn get(&self, index: u64) -> Option<T> {
        let key = index.to_be_bytes();

        self.db
            .get(0, &key)
            .unwrap()
            .map(|data| T::try_from_slice(data.as_slice()).unwrap())
    }

    pub fn iter(&self) -> SparseArrayIter<T> {
        SparseArrayIter {
            inner: self.db.iter(0),
            _phantom: Default::default(),
        }
    }

    pub fn iter_slice(&self, range: RangeInclusive<u64>) -> impl Iterator<Item = (u64, T)> + '_ {
        self.iter()
            .take_while(move |(index, _)| range.contains(index))
    }

    pub fn set(&mut self, index: u64, data: &T) {
        let mut batch = self.db.transaction();
        self.set_batched(index, data, &mut batch);
        self.db.write(batch).unwrap();
    }

    pub fn set_multiple<'a, I>(&mut self, items: I)
    where
        I: IntoIterator<Item = &'a (u64, T)>,
    {
        let mut batch = self.db.transaction();

        for (index, item) in items {
            self.set_batched(*index, item, &mut batch);
        }

        self.db.write(batch).unwrap();
    }

    fn set_batched(&mut self, index: u64, data: &T, batch: &mut DBTransaction) {
        let key = index.to_be_bytes();
        let data = data.try_to_vec().unwrap();

        batch.put(0, &key, &data);
    }
}

pub struct SparseArrayIter<'a, T: BorshDeserialize> {
    inner: Box<dyn Iterator<Item = (Box<[u8]>, Box<[u8]>)> + 'a>,
    _phantom: PhantomData<T>,
}

impl<'a, T: BorshDeserialize> Iterator for SparseArrayIter<'a, T> {
    type Item = (u64, T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(key, value)| {
            let key = TryFrom::try_from(key.as_ref()).unwrap();
            let index = u64::from_be_bytes(key);
            let data = T::try_from_slice(&value).unwrap();

            (index, data)
        })
    }
}
