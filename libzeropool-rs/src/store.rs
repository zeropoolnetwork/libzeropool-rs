pub use kvdb::*;
pub use kvdb_memorydb::InMemory as MemoryDatabase;
#[cfg(feature = "native")]
pub use kvdb_persy::PersyDatabase as NativeDatabase;
#[cfg(feature = "web")]
pub use kvdb_web::Database as WebDatabase;
