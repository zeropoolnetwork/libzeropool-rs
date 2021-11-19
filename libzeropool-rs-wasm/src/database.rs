#[cfg(not(feature = "bundler"))]
pub use kvdb_memorydb::InMemory as Database;
#[cfg(feature = "bundler")]
pub use kvdb_web::Database;
