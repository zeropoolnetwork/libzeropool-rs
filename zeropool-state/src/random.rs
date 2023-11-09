use getrandom::getrandom;
use libzeropool::fawkes_crypto::rand::{Error as RandError, RngCore};

#[derive(Debug)]
struct ErrorWrapper(getrandom::Error);

impl std::error::Error for ErrorWrapper {}

impl std::fmt::Display for ErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
#[derive(Default)]
pub struct CustomRng;

impl RngCore for CustomRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0; std::mem::size_of::<u32>()];
        getrandom(&mut buf).expect("getrandom failed");

        u32::from_ne_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf = [0; std::mem::size_of::<u64>()];
        getrandom(&mut buf).expect("getrandom failed");

        u64::from_ne_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        getrandom(dest).expect("getrandom failed");
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        getrandom(dest).map_err(|err| RandError::new(ErrorWrapper(err)))
    }
}
