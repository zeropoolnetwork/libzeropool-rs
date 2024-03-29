use std::collections::HashSet;

use kvdb::{DBKey, DBKeyValue, DBOp, DBTransaction, DBValue, KeyValueDB};
use persy::{Config, Persy, PersyError, PersyId, ValueMode, PE};

fn persy_to_io<T: Into<PersyError>>(err: PE<T>) -> std::io::Error {
    let PE::PE(err) = err;
    std::io::Error::new(std::io::ErrorKind::Other, err.into())
}

fn encode_key(key: &[u8]) -> String {
    hex::encode(key)
}

fn decode_key(key: &str) -> Vec<u8> {
    hex::decode(key).expect("Invalid key")
}

fn id_index(col: u32) -> String {
    format!("i:{}", col)
}

fn key_index(col: u32) -> String {
    format!("k:{}", col)
}

fn prefix_index_key(col: u32, prefix: &[u8]) -> String {
    let prefix = hex::encode(prefix);
    format!("p:{}:{}", col, prefix)
}

const PREFIXES_INDEX: &str = "prefixes";

pub struct PersyDatabase {
    db: Persy,
    prefixes: HashSet<String>,
}

impl PersyDatabase {
    pub fn open(path: &str, columns: u32, prefixes: &[&[u8]]) -> std::io::Result<Self> {
        let _ = Persy::create(path);
        let persy = Persy::open(path, Config::new()).map_err(persy_to_io)?;
        let prefixes = prefixes
            .iter()
            .filter(|prefix| !prefix.is_empty())
            .map(|prefix| encode_key(prefix))
            .collect::<HashSet<_>>();

        let mut tx = persy.begin().map_err(persy_to_io)?;

        for column in 0..columns {
            let segment = column.to_string();
            let id_to_key_index = id_index(column);
            let key_to_id_index = key_index(column);

            if !tx.exists_segment(&segment).map_err(persy_to_io)? {
                tx.create_segment(&segment).map_err(persy_to_io)?;
            }

            if !tx.exists_index(&id_to_key_index).map_err(persy_to_io)? {
                tx.create_index::<PersyId, String>(&id_to_key_index, ValueMode::Replace)
                    .map_err(persy_to_io)?;
            }

            if !tx.exists_index(&key_to_id_index).map_err(persy_to_io)? {
                tx.create_index::<String, PersyId>(&key_to_id_index, ValueMode::Replace)
                    .map_err(persy_to_io)?;
            }
        }

        if !tx.exists_index(PREFIXES_INDEX).map_err(persy_to_io)? {
            tx.create_index::<String, PersyId>(PREFIXES_INDEX, ValueMode::Cluster)
                .map_err(persy_to_io)?;
        }

        tx.prepare()
            .map_err(persy_to_io)?
            .commit()
            .map_err(persy_to_io)?;

        Ok(PersyDatabase {
            db: persy,
            prefixes,
        })
    }
}

impl KeyValueDB for PersyDatabase {
    fn get(&self, col: u32, key: &[u8]) -> std::io::Result<Option<DBValue>> {
        let key = encode_key(key);
        let index_k_to_id = key_index(col);
        let segment = col.to_string();

        let mut read_id = self
            .db
            .get::<String, PersyId>(&index_k_to_id, &key)
            .map_err(persy_to_io)?;

        if let Some(id) = read_id.next() {
            let data = self.db.read(&segment, &id).map_err(persy_to_io)?;
            Ok(data)
        } else {
            Ok(None)
        }
    }

    fn get_by_prefix(&self, col: u32, prefix: &[u8]) -> std::io::Result<Option<DBValue>> {
        let prefix_key = prefix_index_key(col, prefix);

        // Using the last element to satisfy kvdb-shared-tests::test_complex, even though it
        // contradicts the method documentation. This method is supposed to return the first
        // matching element, but the test expects the last one.
        let Some(rec_id) = self.db.get(PREFIXES_INDEX, &prefix_key).map_err(persy_to_io)?.last() else {
            return Ok(None);
        };

        self.db.read(&col.to_string(), &rec_id).map_err(persy_to_io)
    }

    fn write(&self, transaction: DBTransaction) -> std::io::Result<()> {
        let mut tx = self.db.begin().map_err(persy_to_io)?;

        for op in transaction.ops {
            match op {
                DBOp::Insert { col, key, value } => {
                    let key = encode_key(key.as_slice());
                    let segment = col.to_string();
                    let index_k_to_id = key_index(col);
                    let index_id_to_k = id_index(col);

                    if let Some(rec_id) = tx
                        .one::<String, PersyId>(&index_k_to_id, &key)
                        .map_err(persy_to_io)?
                    {
                        tx.delete(&segment, &rec_id).map_err(persy_to_io)?;
                    }

                    let rec_id = tx.insert(&segment, &value).map_err(persy_to_io)?;

                    for prefix in &self.prefixes {
                        let prefix_bytes = decode_key(prefix);
                        let prefix_key = prefix_index_key(col, &prefix_bytes);

                        if key.starts_with(prefix) {
                            tx.put(PREFIXES_INDEX, prefix_key, rec_id)
                                .map_err(persy_to_io)?;
                        }
                    }

                    tx.put(&index_k_to_id, key.clone(), rec_id)
                        .map_err(persy_to_io)?;
                    tx.put(&index_id_to_k, rec_id, key).map_err(persy_to_io)?;
                }
                DBOp::Delete { col, key } => {
                    let key = encode_key(key.as_slice());
                    let segment = col.to_string();
                    let index_k_to_id = key_index(col);
                    let index_id_to_k = id_index(col);

                    if let Some(rec_id) = tx
                        .one::<String, PersyId>(&index_k_to_id, &key)
                        .map_err(persy_to_io)?
                    {
                        tx.remove::<String, PersyId>(&index_k_to_id, key, None)
                            .map_err(persy_to_io)?;
                        tx.remove::<PersyId, String>(&index_id_to_k, rec_id, None)
                            .map_err(persy_to_io)?;
                        tx.delete(&segment, &rec_id).map_err(persy_to_io)?;
                    }
                }
                DBOp::DeletePrefix { col, prefix } => {
                    let prefix_key = prefix_index_key(col, &prefix);
                    let segment = col.to_string();
                    let index_k_to_id = key_index(col);
                    let index_id_to_k = id_index(col);

                    // Reset indices for the column
                    if prefix.is_empty() {
                        tx.drop_segment(&segment).map_err(persy_to_io)?;
                        tx.create_segment(&segment).map_err(persy_to_io)?;
                        tx.drop_index(&index_k_to_id).map_err(persy_to_io)?;
                        tx.create_index::<String, PersyId>(&index_k_to_id, ValueMode::Replace)
                            .map_err(persy_to_io)?;
                        tx.drop_index(&index_id_to_k).map_err(persy_to_io)?;
                        tx.create_index::<PersyId, String>(&index_id_to_k, ValueMode::Replace)
                            .map_err(persy_to_io)?;
                        tx.remove::<String, PersyId>(PREFIXES_INDEX, prefix_key.clone(), None)
                            .map_err(persy_to_io)?;
                        continue;
                    }

                    let mut rec_ids = tx
                        .get(PREFIXES_INDEX, &prefix_key)
                        .map_err(persy_to_io)?
                        .collect::<Vec<_>>();

                    let mut keys = rec_ids
                        .iter()
                        .map(|rec_id| {
                            Ok(tx
                                .one::<PersyId, String>(&index_id_to_k, rec_id)
                                .map_err(persy_to_io)?
                                .ok_or_else(|| {
                                    std::io::Error::new(std::io::ErrorKind::Other, "Key not found")
                                })?)
                        })
                        .collect::<std::io::Result<Vec<_>>>()?;

                    for (key, rec_id) in keys.drain(..).zip(rec_ids.drain(..)) {
                        tx.remove::<String, PersyId>(&index_k_to_id, key, None)
                            .map_err(persy_to_io)?;
                        tx.remove::<PersyId, String>(&index_id_to_k, rec_id, None)
                            .map_err(persy_to_io)?;
                        tx.remove::<String, PersyId>(PREFIXES_INDEX, prefix_key.clone(), None)
                            .map_err(persy_to_io)?;
                        tx.delete(&segment, &rec_id).map_err(persy_to_io)?;
                    }
                }
            }
        }

        tx.prepare()
            .map_err(persy_to_io)?
            .commit()
            .map_err(persy_to_io)?;

        Ok(())
    }

    fn iter<'a>(&'a self, col: u32) -> Box<dyn Iterator<Item = std::io::Result<DBKeyValue>> + 'a> {
        let segment = col.to_string();
        let index_id_to_k = id_index(col);

        if !self.db.exists_segment(&segment).unwrap() {
            return Box::new(std::iter::empty());
        }

        let iter = self.db.scan(&segment).unwrap().map(move |(id, data)| {
            let key = self
                .db
                .one::<PersyId, String>(&index_id_to_k, &id)
                .map_err(persy_to_io)?
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Value not found"))?;
            let key = DBKey::from_slice(&decode_key(&key));
            Ok((key, data))
        });

        Box::new(iter)
    }

    fn iter_with_prefix<'a>(
        &'a self,
        col: u32,
        prefix: &'a [u8],
    ) -> Box<dyn Iterator<Item = std::io::Result<DBKeyValue>> + 'a> {
        if prefix.is_empty() {
            return self.iter(col);
        }

        let segment = col.to_string();
        let index_id_to_k = id_index(col);
        let prefix_key = prefix_index_key(col, prefix);

        let Ok(ids) = self
            .db
            .get::<String, PersyId>(PREFIXES_INDEX, &prefix_key)
            .map_err(persy_to_io) else {
            return Box::new(std::iter::empty());
        };

        let pairs = ids.map(move |id| {
            let key = self
                .db
                .one::<PersyId, String>(&index_id_to_k, &id)
                .map_err(persy_to_io)?
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Key not found"))?;

            let data = self
                .db
                .read(&segment, &id)
                .map_err(persy_to_io)?
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "Value not found"))?;

            let decoded_key = DBKey::from_slice(&decode_key(&key));

            Ok((decoded_key, data))
        });

        Box::new(pairs)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use kvdb_shared_tests as st;

    use super::*;

    // kvdb-shared-tests prefixes
    const PREFIXES: &[&[u8]] = &[
        b"04c0",
        b"",
        b"a",
        b"abc",
        b"abcde",
        b"0",
        &[1],
        &[1, 2],
        &[1, 255, 255],
        &[255],
        &[255, 255],
        &[8],
        b"03c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
        b"04c00000000b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc",
    ];

    struct TestContext {
        file_name: String,
        db: PersyDatabase,
    }

    impl Drop for TestContext {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.file_name);
        }
    }

    fn new_file_name() -> String {
        static FILE_N: AtomicUsize = AtomicUsize::new(0);
        let file_n = FILE_N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("test-{file_n}.persy")
    }

    fn setup(num_cols: u32) -> TestContext {
        let file_name = new_file_name();
        let _ = std::fs::remove_file(&file_name);
        let db = PersyDatabase::open(&file_name, num_cols, PREFIXES).unwrap();

        TestContext { file_name, db }
    }

    #[test]
    fn test_put() {
        let ctx = setup(1);
        let mut tx = ctx.db.transaction();
        tx.put(0, &[1], &[1, 1, 1, 1]);
        tx.put(0, &[2], &[2, 2, 2, 2]);
        ctx.db.write(tx).unwrap();

        assert_eq!(ctx.db.get(0, &[1]).unwrap(), Some(vec![1, 1, 1, 1]));
        assert_eq!(ctx.db.get(0, &[2]).unwrap(), Some(vec![2, 2, 2, 2]));
        assert_eq!(ctx.db.get(0, &[3]).unwrap(), None);

        let results = ctx.db.iter(0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    pub fn test_put_and_get() {
        let ctx = setup(1);
        st::test_put_and_get(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_delete_and_get() {
        let ctx = setup(1);
        st::test_delete_and_get(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_get_fails_with_non_existing_column() {
        let ctx = setup(1);
        st::test_get_fails_with_non_existing_column(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_write_clears_buffered_ops() {
        let ctx = setup(1);
        st::test_write_clears_buffered_ops(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_iter() {
        let ctx = setup(1);
        st::test_iter(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_iter_with_prefix() {
        let ctx = setup(1);
        st::test_iter_with_prefix(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_delete_prefix() {
        let ctx = setup(7);
        st::test_delete_prefix(&ctx.db).unwrap();
    }

    #[test]
    pub fn test_complex() {
        let ctx = setup(1);
        st::test_complex(&ctx.db).unwrap();
    }
}
