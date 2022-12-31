use std::collections::HashSet;

use kvdb::{DBKeyValue, DBOp, DBTransaction, DBValue, KeyValueDB};
use persy::{Config, Persy, PersyError, PersyId, ValueMode, PE};
use smallvec::SmallVec;

fn persy_to_io<T: Into<PersyError>>(err: PE<T>) -> std::io::Error {
    let PE::PE(err) = err;
    std::io::Error::new(std::io::ErrorKind::Other, err.into())
}

fn encode_key(key: &[u8]) -> String {
    hex::encode(key)
}

fn decode_key(key: &str) -> Vec<u8> {
    hex::decode(key).unwrap()
}

pub struct PersyDatabase {
    db: Persy,
    prefixes: HashSet<String>,
}

// #[cfg(test)]
// impl Drop for PersyDatabase {
//     fn drop(&mut self) {
//         self.db.free_file_lock().unwrap();
//     }
// }

impl PersyDatabase {
    pub fn open(path: &str, prefixes: &[&[u8]]) -> std::io::Result<Self> {
        let _ = Persy::create(path);
        let persy = Persy::open(path, Config::new()).map_err(persy_to_io)?;
        let prefixes = prefixes
            .iter()
            .map(|prefix| encode_key(prefix))
            .collect::<HashSet<_>>();

        let mut tx = persy.begin().map_err(persy_to_io)?;

        for prefix in &prefixes {
            if !tx.exists_index(prefix).map_err(persy_to_io)? {
                tx.create_index::<String, PersyId>(prefix, ValueMode::Replace)
                    .map_err(persy_to_io)?;
            }
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
        let col = col.to_string();
        let mut read_id = self
            .db
            .get::<String, PersyId>(&col, &key)
            .map_err(persy_to_io)?;

        if let Some(id) = read_id.next() {
            let data = self.db.read(&col, &id).map_err(persy_to_io)?;
            Ok(data)
        } else {
            Ok(None)
        }
    }

    fn get_by_prefix(&self, col: u32, prefix: &[u8]) -> std::io::Result<Option<DBValue>> {
        todo!()
    }

    fn write(&self, transaction: DBTransaction) -> std::io::Result<()> {
        let mut tx = self.db.begin().map_err(persy_to_io)?;

        for op in transaction.ops {
            match op {
                DBOp::Insert { col, key, value } => {
                    let key = encode_key(key.as_slice());
                    let segment = col.to_string();
                    let index_k_to_id = format!("k{col}");
                    let index_id_to_k = format!("id{col}");

                    if !tx.exists_segment(&segment).map_err(persy_to_io)? {
                        tx.create_segment(&segment).map_err(persy_to_io)?;
                    }

                    if !tx.exists_index(&index_k_to_id).map_err(persy_to_io)? {
                        tx.create_index::<String, PersyId>(&index_k_to_id, ValueMode::Replace)
                            .map_err(persy_to_io)?;
                    }

                    if !tx.exists_index(&index_id_to_k).map_err(persy_to_io)? {
                        tx.create_index::<PersyId, String>(&index_id_to_k, ValueMode::Replace)
                            .map_err(persy_to_io)?;
                    }

                    // FIXME: check if the key exists before inserting
                    let rec_id = tx.insert(&segment, &value).map_err(persy_to_io)?;

                    for prefix in &self.prefixes {
                        if key.starts_with(prefix) {
                            tx.put(prefix, key.clone(), rec_id).map_err(persy_to_io)?;
                        }
                    }

                    tx.put(&index_k_to_id, key.clone(), rec_id)
                        .map_err(persy_to_io)?;
                    tx.put(&index_id_to_k, rec_id, key).map_err(persy_to_io)?;
                }
                DBOp::Delete { col, key } => {
                    let key = encode_key(key.as_slice());
                    let segment = col.to_string();
                    let index_k_to_id = format!("k{col}");
                    let index_id_to_k = format!("id{col}");

                    let rec_id = tx
                        .one::<String, PersyId>(&index_k_to_id, &key)
                        .map_err(persy_to_io)?
                        .unwrap(); // FIXME
                    tx.remove::<String, PersyId>(&index_k_to_id, key, None)
                        .map_err(persy_to_io)?;
                    tx.remove::<PersyId, String>(&index_id_to_k, rec_id, None)
                        .map_err(persy_to_io)?;
                    tx.delete(&segment, &rec_id).map_err(persy_to_io)?;
                }
                DBOp::DeletePrefix { col, prefix } => {
                    // let prefix = encode_key(prefix);
                    // let col = col.to_string();
                    todo!()
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
        let index_id_to_k = format!("id{col}");

        Box::new(self.db.scan(&segment).unwrap().map(move |(id, data)| {
            let key = self
                .db
                .one::<PersyId, String>(&index_id_to_k, &id)
                .map_err(persy_to_io)?
                .unwrap(); // FIXME
            let key = SmallVec::from_slice(&decode_key(&key));
            Ok((key, data))
        }))
    }

    fn iter_with_prefix<'a>(
        &'a self,
        col: u32,
        prefix: &'a [u8],
    ) -> Box<dyn Iterator<Item = std::io::Result<DBKeyValue>> + 'a> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open() {
        let db = PersyDatabase::open("./test.persy", &[]).unwrap();
        // for _ in 0..10 {
        //     let db = PersyDatabase::open("./test.persy", &[]).unwrap();
        //     drop(db);
        // }
    }

    #[test]
    fn test_put() {
        let db = PersyDatabase::open("./test.persy", &[]).unwrap();
        let mut tx = db.transaction();
        tx.put(0, &[1, 2, 3, 4], &[1, 1, 1, 1]);
        db.write(tx).unwrap();

        let results = db.iter(0).collect::<Result<Vec<_>, _>>().unwrap();
        assert_eq!(results.len(), 2);
    }
}
