#[cfg(not(any(feature = "bundler", feature = "web")))]
pub use kvdb_memorydb::InMemory as Database;
#[cfg(any(feature = "bundler", feature = "web"))]
pub use kvdb_web::Database;
